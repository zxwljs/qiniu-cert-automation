#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把本地证书同步到七牛云 Kodo / CDN 域名。

流程：上传证书 -> 更新源站域名 HTTPS 配置 -> 更新 CDN 加速域名 HTTPS 配置 -> 清理旧证书

依赖全部来自 Python 标准库，不需要 pip install 任何东西。

环境变量（GitHub Actions Secrets 里配好后由 workflow 注入）：
    QINIU_AK        七牛云 AccessKey
    QINIU_SK        七牛云 SecretKey
    QINIU_DOMAIN    要绑定的域名，例如 img.example.com
    CERT_DIR        acme.sh --install-cert 的输出目录，里面有 fullchain.pem / privkey.pem
    FORCE_HTTPS     可选，"1"/"true" 时开启 HTTP 强制跳 HTTPS，默认 0
    CERT_STATE_FILE 可选，证书指纹状态文件路径，默认 ${CERT_DIR}/.qiniu-sync-state.json
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

FUSION_HOST = "fusion.qiniuapi.com"   # 证书管理、缓存刷新
API_HOST = "api.qiniu.com"            # 域名管理 / HTTPS 配置

QINIU_AK = os.environ.get("QINIU_AK", "").strip()
QINIU_SK = os.environ.get("QINIU_SK", "").strip()
DOMAIN = os.environ.get("QINIU_DOMAIN", "").strip().lower()
CERT_DIR = os.environ.get("CERT_DIR", "").strip()
FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "0").strip().lower() in ("1", "true", "yes")
STATE_FILE = os.environ.get(
    "CERT_STATE_FILE", os.path.join(CERT_DIR, ".qiniu-sync-state.json")
) if CERT_DIR else ""

log_prefix = "[qiniu-sync]"


def log(msg):
    print(f"{log_prefix} {msg}", flush=True)


def die(msg):
    print(f"{log_prefix} ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


# --------------------------------------------------------------------------
# 鉴权
# --------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def qbox_token(path_with_query: str) -> str:
    """QBox 鉴权：签名串 = 路径(含 query) + "\n"，不带域名。"""
    sign_str = path_with_query + "\n"
    sig = hmac.new(QINIU_SK.encode(), sign_str.encode(), hashlib.sha1).digest()
    return f"QBox {QINIU_AK}:{b64url(sig)}"


def qiniu_token(method: str, host: str, path: str, content_type: str, body: str):
    """Qiniu 鉴权：签名字段串，必须配合 X-Qiniu-Date 请求头。返回 (token, date_str)"""
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
        f"https://{FUSION_HOST}{path_with_query}",
        "GET",
        qbox_token(path_with_query),
    )


def fusion_post(path, payload):
    body = json.dumps(payload, separators=(",", ":"))
    return api_request(
        f"https://{FUSION_HOST}{path}", "POST", qbox_token(path), body
    )


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


def cert_fingerprint(cert_pem):
    return hashlib.sha256(cert_pem.encode()).hexdigest()


def cert_not_after(cert_pem):
    """不依赖第三方库，直接用 openssl 拿到期时间；拿不到就返回 None。"""
    path = os.path.join(CERT_DIR, "fullchain.pem")
    try:
        import subprocess

        out = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-enddate"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if out.returncode != 0:
            return None
        raw = out.stdout.strip().split("=", 1)[-1]
        dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def check_expiry(cert_pem):
    """七牛要求证书有效期 >= 30 天。"""
    dt = cert_not_after(cert_pem)
    if dt is None:
        log("WARN: 无法解析证书到期时间（openssl 不可用），跳过有效期检查")
        return
    days = (dt - datetime.now(timezone.utc)).days
    log(f"证书到期时间 {dt.strftime('%Y-%m-%d')}，剩余 {days} 天")
    if days < 30:
        die(f"证书剩余有效期仅 {days} 天，不满足七牛 >= 30 天的要求，拒绝上传")


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
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# 各步骤
# --------------------------------------------------------------------------
def upload_cert(cert_pem, key_pem):
    name = f"{DOMAIN}-letsencrypt-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    payload = {
        "name": name,
        "commonName": DOMAIN,
        "pri": key_pem,
        "ca": cert_pem,
    }
    res = fusion_post("/sslcert", payload)
    cert_id = res.get("certID") or res.get("certId") or (res.get("data") or {}).get("certID")
    if not cert_id:
        die(f"上传证书接口未返回 certID，原始响应: {res}")
    log(f"证书上传成功，certID={cert_id}，name={name}")
    return cert_id


def update_origin_domain(cert_id):
    """源站绑定域名。只在用户确实绑了源站域名时才会成功，失败不阻断主流程。"""
    path = f"/domain/{DOMAIN}/httpsconf"
    payload = {
        "certId": cert_id,
        "forceHttps": FORCE_HTTPS,
        "http2Enable": True,
        "tlsVersions": "TLSv1.2",
    }
    try:
        res = api_write("PUT", path, payload)
        log(f"源站域名 HTTPS 配置已更新: {res}")
        return True
    except Exception as e:
        log(f"WARN: 源站域名 HTTPS 配置更新跳过（可能未绑定源站域名）: {e}")
        return False


def update_cdn_domain(cert_id):
    """CDN 加速域名 HTTPS 配置。核心步骤，失败直接报错。"""
    path = f"/domain/{DOMAIN}/httpsconf"
    payload = {
        "certId": cert_id,
        "forceHttps": FORCE_HTTPS,
        "http2Enable": True,
        "tlsVersions": "TLSv1.2",
    }
    res = api_write("PUT", path, payload)
    log(f"CDN 加速域名 HTTPS 配置已更新: {res}")
    return res


def list_certs():
    marker = ""
    certs = []
    while True:
        path = f"/sslcert?limit=100&marker={marker}"
        try:
            res = fusion_get(path)
        except Exception as e:
            log(f"WARN: 拉取证书列表失败: {e}")
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
    """只删除同域名、且不是当前在用的证书。"""
    keep = str(cert_id)
    removed = 0
    for c in list_certs():
        cid = str(c.get("certID") or c.get("certId") or "")
        cn = (c.get("commonName") or c.get("name") or "").lower()
        if not cid or cid == keep:
            continue
        if DOMAIN not in cn and not cn.startswith(f"{DOMAIN}-"):
            continue
        try:
            res = api_request(
                f"https://{FUSION_HOST}/sslcert/{cid}",
                "DELETE",
                qbox_token(f"/sslcert/{cid}"),
            )
            log(f"已删除旧证书 {cid} ({c.get('name')}) -> {res}")
            removed += 1
        except Exception as e:
            log(f"WARN: 删除旧证书 {cid} 失败: {e}")
    log(f"旧证书清理完成，共删除 {removed} 张")


def verify_online():
    """从公网验证一次，确认新证书真的生效。"""
    import ssl
    import socket

    target = DOMAIN
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
                log(f"线上验证通过: {target}:443 签发机构={issuer} 到期={not_after}")
    except Exception as e:
        log(f"WARN: 线上验证未通过（证书可能需要几分钟生效）: {e}")


# --------------------------------------------------------------------------
def main():
    if not QINIU_AK or not QINIU_SK:
        die("缺少 QINIU_AK / QINIU_SK 环境变量")
    if not DOMAIN:
        die("缺少 QINIU_DOMAIN 环境变量")
    if not CERT_DIR:
        die("缺少 CERT_DIR 环境变量")

    log(f"域名={DOMAIN}  证书目录={CERT_DIR}  强制HTTPS={'开' if FORCE_HTTPS else '关'}")

    cert_pem = read_pem("fullchain.pem")
    key_pem = read_pem("privkey.pem")
    check_expiry(cert_pem)

    fp = cert_fingerprint(cert_pem)
    state = load_state()

    if state.get("fingerprint") == fp and not os.environ.get("FORCE_UPLOAD"):
        log("证书指纹与上次同步一致，跳过上传（如需强制重建请设置 FORCE_UPLOAD=1）")
        verify_online()
        return 0

    cert_id = upload_cert(cert_pem, key_pem)
    update_origin_domain(cert_id)
    update_cdn_domain(cert_id)

    save_state({
        "fingerprint": fp,
        "certId": cert_id,
        "domain": DOMAIN,
        "syncedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })

    cleanup_old_certs(cert_id)
    time.sleep(3)
    verify_online()
    log("同步流程全部完成")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        die(str(e))