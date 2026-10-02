#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把本地证书同步到七牛云 Kodo / CDN 域名。

一条证书可以同时绑定多个七牛域名，所以证书只上传一次，
再逐个把各个域名换绑到这张新证书上。

环境变量（GitHub Actions Secrets 注入）：
    QINIU_AK        七牛云 AccessKey                     必填
    QINIU_SK        七牛云 SecretKey                     必填
    QINIU_DOMAIN    七牛域名，多个用英文逗号分隔          必填
                    例：img.example.com,static.example.com
    CERT_DIR        acme.sh --install-cert 的输出目录      必填
                    里面需有 fullchain.pem 和 privkey.pem
    FORCE_HTTPS     可选，"1"/"true" 时 HTTP 强制跳 HTTPS，默认 "0"
    CERT_STATE_FILE 可选，证书指纹状态文件路径
                    默认 ${CERT_DIR}/.qiniu-sync-state.json

只依赖 Python 标准库，不需要 pip install 任何东西。
"""

import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

FUSION_HOST = "fusion.qiniuapi.com"   # 证书管理、缓存刷新
API_HOST = "api.qiniu.com"            # 域名管理 / HTTPS 配置

QINIU_AK = os.environ.get("QINIU_AK", "").strip()
QINIU_SK = os.environ.get("QINIU_SK", "").strip()
RAW_DOMAINS = os.environ.get("QINIU_DOMAIN", "").strip()
DOMAINS = [d.strip().lower() for d in RAW_DOMAINS.split(",") if d.strip()]
CERT_DIR = os.environ.get("CERT_DIR", "").strip()
FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "0").strip().lower() in ("1", "true", "yes")
STATE_FILE = (
    os.environ.get("CERT_STATE_FILE", "").strip()
    or (os.path.join(CERT_DIR, ".qiniu-sync-state.json") if CERT_DIR else "")
)
MIN_REMAIN_DAYS = int(os.environ.get("MIN_REMAIN_DAYS", "30"))

log_prefix = "[qiniu-sync]"


def log(msg):
    print(f"{log_prefix} {msg}", flush=True)


def warn(msg):
    print(f"{log_prefix} WARN: {msg}", flush=True)


def die(msg):
    print(f"{log_prefix} ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


# --------------------------------------------------------------------------
# 七牛两套鉴权：QBox 与 Qiniu，签名方式不同，不可混用
# --------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def qbox_token(path_with_query: str) -> str:
    """QBox：签名串 = 路径(含 query) + "\\n"，不含域名。用于 fusion.qiniuapi.com。"""
    sign_str = path_with_query + "\n"
    sig = hmac.new(QINIU_SK.encode(), sign_str.encode(), hashlib.sha1).digest()
    return f"QBox {QINIU_AK}:{b64url(sig)}"


def qiniu_token(method: str, host: str, path: str, content_type: str, body: str):
    """Qiniu：签名字段串，必须配合 X-Qiniu-Date 请求头一起返回。用于 api.qiniu.com。"""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sign_str = f"{method.upper()} {path}\nHost: {host}\n"
    if content_type and body is not None:
        sign_str += f"Content-Type: {content_type}\n"
    sign_str += f"X-Qiniu-Date: {date_str}\n\n"
    if body:
        sign_str += body
    sig = hmac.new(QINIU_SK.encode(), sign_str.encode(), hashlib.sha1).digest()
    return f"Qiniu {QINIU_AK}:{b64url(sig)}", date_str


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def api_request(url, method, token, body=None, extra_headers=None):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        raise RuntimeError(f"HTTP {e.code}: {raw}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error: {e}") from None

    result = json.loads(raw) if raw else {}
    # 七牛不同接口成功时 code 可能是 200 也可能是 0，两个都放过
    code = result.get("code")
    if code is not None and code not in (0, 200):
        raise RuntimeError(f"API error {code}: {result.get('error', 'unknown')}")
    return result


def fusion_get(path_with_query):
    return api_request(
        f"https://{FUSION_HOST}{path_with_query}", "GET", qbox_token(path_with_query)
    )


def fusion_delete(path):
    return api_request(f"https://{FUSION_HOST}{path}", "DELETE", qbox_token(path))


def api_write(method, path, payload):
    body = json.dumps(payload, separators=(",", ":"))
    token, date_str = qiniu_token(method, API_HOST, path, "application/json", body)
    return api_request(
        f"https://{API_HOST}{path}",
        method,
        token,
        body,
        extra_headers={"X-Qiniu-Date": date_str},
    )


# --------------------------------------------------------------------------
# 证书读取与校验
# --------------------------------------------------------------------------
def read_pem(filename):
    path = os.path.join(CERT_DIR, filename)
    if not os.path.isfile(path):
        die(f"证书文件不存在: {path}")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    if not content or content.lower() == "null":
        die(f"证书文件为空: {path}")
    return content


def cert_not_after(cert_path):
    """用 openssl 拿到期时间，拿不到返回 None。"""
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if out.returncode != 0:
            return None
        raw = out.stdout.strip().split("=", 1)[-1]
        return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def check_expiry(cert_path):
    """七牛要求证书剩余有效期 >= 30 天，不足会拒收。"""
    dt = cert_not_after(cert_path)
    if dt is None:
        warn("无法解析证书到期时间（openssl 不可用？），跳过有效期检查")
        return
    days = (dt - datetime.now(timezone.utc)).days
    log(f"证书到期时间 {dt.strftime('%Y-%m-%d')}，剩余 {days} 天")
    if days < MIN_REMAIN_DAYS:
        die(
            f"证书剩余有效期仅 {days} 天，不满足七牛 >= {MIN_REMAIN_DAYS} 天的要求，拒绝上传"
        )


def load_state():
    if not STATE_FILE or not os.path.isfile(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    if not STATE_FILE:
        return
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# 各步骤
# --------------------------------------------------------------------------
def upload_cert(cert_pem, key_pem):
    """证书只上传一次，返回 certID。所有域名共用这一张。"""
    name = f"le-{'-'.join(DOMAINS)[:50]}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    payload = {
        "name": name,
        "commonName": DOMAINS[0],
        "pri": key_pem,
        "ca": cert_pem,
    }
    res = api_request(
        f"https://{FUSION_HOST}/sslcert",
        "POST",
        qbox_token("/sslcert"),
        json.dumps(payload, separators=(",", ":")),
    )
    cert_id = (
        res.get("certID")
        or res.get("certId")
        or (res.get("data") or {}).get("certID")
    )
    if not cert_id:
        die(f"上传证书接口未返回 certID，原始响应: {res}")
    log(f"证书上传成功，certID={cert_id}，name={name}")
    return cert_id


def bind_domain(domain, cert_id):
    """把单个域名换绑到指定证书。"""
    path = f"/domain/{domain}/httpsconf"
    payload = {
        "certId": cert_id,
        "forceHttps": FORCE_HTTPS,
        "http2Enable": True,
        "tlsVersions": "TLSv1.2",
    }
    return api_write("PUT", path, payload)


def bind_all_domains(cert_id):
    """逐个域名换绑。单域失败不阻断其它域，最后统一汇报。"""
    ok, failed = [], []
    for domain in DOMAINS:
        try:
            res = bind_domain(domain, cert_id)
            log(f"  [OK] {domain} 换绑成功: {res}")
            ok.append(domain)
        except Exception as e:
            err = str(e)
            # 域名未绑定/未备案属配置问题，重试无意义
            log(f"  [FAIL] {domain} 换绑失败: {err}")
            failed.append((domain, err))
    if not ok:
        die(f"所有域名换绑都失败了，首个错误: {failed[0][1] if failed else '未知'}")
    return ok, failed


def list_certs():
    marker = ""
    certs = []
    while True:
        path = f"/sslcert?limit=100&marker={marker}"
        try:
            res = fusion_get(path)
        except Exception as e:
            warn(f"拉取证书列表失败: {e}")
            return certs
        batch = res.get("certs") or (res.get("data") or {}).get("certs") or []
        if not batch:
            break
        certs.extend(batch)
        if len(batch) < 100:
            break
        marker = batch[-1].get("certID") or batch[-1].get("certId") or ""
        if not marker:
            break
    return certs


def cleanup_old_certs(cert_id):
    """删除本项目历史遗留的旧证书。判断条件：名字以 le- 开头（我们自己上传的）。"""
    keep = str(cert_id)
    removed, skipped = 0, 0
    for c in list_certs():
        cid = str(c.get("certID") or c.get("certId") or "")
        cname = (c.get("name") or "")
        if not cid or cid == keep:
            continue
        # 只清理本脚本产生的证书，绝不碰用户手动上传的
        if not cname.startswith("le-"):
            skipped += 1
            continue
        try:
            res = fusion_delete(f"/sslcert/{cid}")
            log(f"已删除旧证书 {cid} ({cname}) -> {res}")
            removed += 1
        except Exception as e:
            warn(f"删除旧证书 {cid} 失败: {e}")
    log(f"旧证书清理完成，删除 {removed} 张，跳过 {skipped} 张非本项目证书")


def verify_online(domain):
    """从公网验证一次，确认新证书真的生效。"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                issuer = dict(x[0] for x in cert.get("issuer", ())).get(
                    "organizationName", "?"
                )
                log(f"  [公网验证通过] {domain}:443  签发机构={issuer}  到期={not_after}")
    except Exception as e:
        warn(f"  [公网验证未通过] {domain}（证书生效可能有几分钟延迟）: {e}")


# --------------------------------------------------------------------------
def main():
    if not QINIU_AK or not QINIU_SK:
        die("缺少 QINIU_AK / QINIU_SK 环境变量")
    if not DOMAINS:
        die("缺少 QINIU_DOMAIN 环境变量")
    if not CERT_DIR:
        die("缺少 CERT_DIR 环境变量")

    log(f"域名: {', '.join(DOMAINS)}")
    log(f"证书目录: {CERT_DIR}  强制HTTPS: {'开' if FORCE_HTTPS else '关'}")

    cert_path = os.path.join(CERT_DIR, "fullchain.pem")
    cert_pem = read_pem("fullchain.pem")
    key_pem = read_pem("privkey.pem")
    check_expiry(cert_path)

    fingerprint = hashlib.sha256(cert_pem.encode()).hexdigest()
    state = load_state()
    force = os.environ.get("FORCE_UPLOAD", "").strip().lower() in ("1", "true", "yes")

    if state.get("fingerprint") == fingerprint and not force:
        log("证书指纹与上次同步一致，跳过上传（强制重建请设 FORCE_UPLOAD=1）")
        for d in DOMAINS:
            verify_online(d)
        return 0

    cert_id = upload_cert(cert_pem, key_pem)
    ok, failed = bind_all_domains(cert_id)

    save_state({
        "fingerprint": fingerprint,
        "certId": cert_id,
        "domains": DOMAINS,
        "syncedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })

    cleanup_old_certs(cert_id)
    log("等待 3 秒后开始公网验证…")
    time.sleep(3)
    for d in ok:
        verify_online(d)

    log(f"同步完成：{len(ok)} 个域名成功" + (f"，{len(failed)} 个失败（见上方日志）" if failed else ""))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        die(str(e))