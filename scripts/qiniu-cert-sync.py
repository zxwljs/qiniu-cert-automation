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


def api_write(method, path, payload, host=None):
    host = host or API_HOST
    body = json.dumps(payload, separators=(",", ":"))
    token, date_str = qiniu_token(method, host, path, "application/json", body)
    return api_request(
        f"https://{host}{path}",
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


UC_HOST = "uc.qiniuapi.com"           # Kodo 空间域名管理


def bind_cdn_domain(domain, cert_id):
    """CDN 加速域名换绑：PUT api.qiniu.com/domain/<d>/httpsconf

    注意：刻意不传 tlsVersions。
    七牛官方文档标注它是 string，但后端 Go 结构体实际是 []fusion.TlsVersion，
    传字符串会报 "cannot unmarshal string into Go struct field"。
    它是选填项，不传就走七牛默认策略。
    """
    path = f"/domain/{domain}/httpsconf"
    payload = {
        "certId": cert_id,
        "forceHttps": FORCE_HTTPS,
        "http2Enable": True,
    }
    return api_write("PUT", path, payload, host=API_HOST)


def bind_kodo_domain_sslcert(domain, cert_id):
    """Kodo 源站域名换绑（/domain/{d}/sslcert 路径）。

    经实测探测：uc.qiniuapi.com 的 /v6/domains/{d}/https 一律返回 404（路径不存在），
    而 /domain/{d}/sslcert 在两个 host 上都返回 401（路径有效，只是本次凭据无效）。
    """
    path = f"/domain/{domain}/sslcert"
    payload = {"certId": cert_id, "forceHttps": FORCE_HTTPS, "http2Enable": True}
    return api_write("PUT", path, payload, host=UC_HOST)


def bind_kodo_domain_sslcert_alt(domain, cert_id):
    """同上，但走 api.qiniu.com（部分接口在此host 下的行为与 fusion 一致）。"""
    path = f"/domain/{domain}/sslcert"
    payload = {"certId": cert_id, "forceHttps": FORCE_HTTPS, "http2Enable": True}
    return api_write("PUT", path, payload, host=API_HOST)


# 依次尝试的换绑策略：(说明, 函数)
# 顺序 = 实测有效性排序。404 = 路径不存在，会立刻跳过，不浪费请求。
BIND_STRATEGIES = [
    ("CDN 加速域名 api.qiniu.com/domain/{d}/httpsconf", bind_cdn_domain),
    ("Kodo 源站域名 uc.qiniuapi.com/domain/{d}/sslcert", bind_kodo_domain_sslcert),
    ("Kodo 源站域名 api.qiniu.com/domain/{d}/sslcert", bind_kodo_domain_sslcert_alt),
]


def bind_one_domain(domain, cert_id):
    """对单个域名依次尝试各接口，返回 (成功方式, 响应, 所有尝试的记录)。"""
    attempts = []
    for label, fn in BIND_STRATEGIES:
        try:
            res = fn(domain, cert_id)
            return label, res, attempts
        except Exception as e:
            attempts.append(f"{label} -> {e}")
    raise RuntimeError("所有接口都失败:\n      " + "\n      ".join(attempts))


def bind_all_domains(cert_id):
    """逐个域名换绑。单域失败不阻断其它域，最后统一汇报。"""
    ok, failed = [], []
    for domain in DOMAINS:
        try:
            label, res, _ = bind_one_domain(domain, cert_id)
            log(f"  [OK] {domain} 换绑成功（{label}）: {res}")
            ok.append(domain)
        except Exception as e:
            err = str(e)
            # 612 no such domain = 域名不在该产品下，换个接口也没用
            # 400xxx = 域名/证书/参数问题，属于配置错误，重试无意义
            fatal = "HTTP 612" in err or "HTTP 400" in err or "HTTP 401" in err
            if fatal:
                die(
                    f"域名 {domain} 换绑失败:\n      {err}\n"
                    f"  证书已成功上传（certID={cert_id}），但换绑失败。\n\n"
                    f"  **七牛的对象存储（Kodo）源站域名很可能不支持 API 换绑** ——\n"
                    f"  这是七牛的产品限制，脚本已尝试全部已知接口路径。\n\n"
                    f"  手动换绑只需 30 秒（换绑后本项目仍会自动续签）：\n"
                    f"   1. 七牛控制台 → SSL 证书服务 → 我的证书\n"
                    f"      找到证书备注名以 le- 开头的（就是刚自动上传的这张）\n"
                    f"   2. 进 Kodo → 空间管理 → 你的空间 → 域名管理\n"
                    f"   3. 点你的域名 → 「配置 HTTPS」→ 开启 http/https\n"
                    f"   4. 更换证书 → 下拉选刚才那张 le-* 证书 → 保存\n\n"
                    f"  注意：证书 90 天后仍需手动换一次。若希望彻底自动化，\n"
                    f"  可考虑改绑 CDN 加速域名（支持 API 换绑，本项目可直接接管）。\n\n"
                    f"  下次重跑会复用 certID={cert_id} 直接重试换绑，不会重复上传证书。"
                )
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

    same_cert = state.get("fingerprint") == fingerprint

    # 情况一：证书没变，且上次换绑也成功了 —— 什么都不用做
    if same_cert and state.get("bound") and not force:
        log("证书指纹与上次同步一致，换绑已完成，跳过（强制重建请设 FORCE_UPLOAD=1）")
        for d in DOMAINS:
            verify_online(d)
        return 0

    # 情况二：证书没变，但上次换绑失败了（或状态丢失）—— 复用已上传的 certID 直接重试，
    # 避免在七牛里堆一叠重复证书
    if same_cert and state.get("certId") and not force:
        cert_id = state["certId"]
        log(f"证书指纹一致，复用已上传的 certID={cert_id}，仅重试换绑")
    else:
        cert_id = upload_cert(cert_pem, key_pem)
        # 先把 certID 落盘：换绑可能失败，但证书已经上传了，
        # 下次重跑要靠这个 certID 复用，不能重复上传
        save_state({
            "fingerprint": fingerprint,
            "certId": cert_id,
            "domains": DOMAINS,
            "uploadedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "bound": False,
        })

    ok, failed = bind_all_domains(cert_id)

    save_state({
        "fingerprint": fingerprint,
        "certId": cert_id,
        "domains": DOMAINS,
        "bound": True,
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