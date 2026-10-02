#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一次性诊断脚本：把七牛所有「疑似域名换绑」端点全部打一遍，找出真正可用的那个。

用法（GitHub Actions: Actions -> probe-qiniu-api -> Run workflow）：
    QINIU_AK / QINIU_SK / QINIU_DOMAIN 从 Secrets 注入
    python3 scripts/probe-qiniu-api.py

【怎么读结果 —— 非常重要】

    404               接口不存在
    401 bad token     该 URL 形状被网关接受了，但**不代表接口存在**
                      （见下面的对照组，乱码 action 也会返回 401）
    612 no such domain 接口存在，但这个域名不属于该产品
    200 / code=0      成功

因为 401 不可信，脚本会同时打一组「乱码对照组」。
判断方法：如果某个真实接口返回 401，而同形状的乱码接口也返回 401，
那么这个 401 没有意义，不能作为「接口存在」的证据。
真正可信的成功信号只有：200、code=0、或者 612（说明域名被识别了，只是不在这个产品里）。
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

AK = os.environ.get("QINIU_AK", "").strip()
SK = os.environ.get("QINIU_SK", "").strip()
DOMAIN = [d.strip().lower() for d in os.environ.get("QINIU_DOMAIN", "").split(",") if d.strip()]
DOMAIN = DOMAIN[0] if DOMAIN else ""

if not AK or not SK or not DOMAIN:
    print("缺少 QINIU_AK / QINIU_SK / QINIU_DOMAIN", file=sys.stderr)
    sys.exit(1)

# 七牛各产品分属不同服务，同一个路径在不同 host 上含义完全不同，必须逐个试。
HOSTS = [
    ("api.qiniu.com", "qiniu"),       # CDN / 融合 CDN 域名管理
    ("api.qiniuapi.com", "qbox"),     # 文档里提到的另一个域名管理入口
    ("uc.qiniuapi.com", "qbox"),      # Kodo 空间与源站域名管理
    ("fusion.qiniuapi.com", "qbox"),  # 证书管理
]

PATHS = [
    "/domain/{d}",
    "/domain/{d}/httpsconf",
    "/domain/{d}/https",
    "/domain/{d}/sslize",
    "/domain/{d}/sslcert",
    "/v6/domain/{d}/httpsconf",
    "/v6/domains/{d}/httpsconf",
    "/v2/domains/{d}/httpsconf",
    "/domains/{d}/httpsconf",
]

# 也许换绑是「把证书部署到域名」，而不是「给域名配证书」。方向反过来路径形状完全不同。
CERT_PATHS = [
    "/sslcert/{c}/bind",
    "/sslcert/{c}/deploy",
    "/sslcert/{c}/domain/{d}",
    "/sslcert/{c}/domains",
]

# 对照组：故意瞎编的 action。它若也返回 401，就证明同形状的 401 全是噪音。
CONTROL = [
    "/domain/{d}/zzz-garbage-action-999",
    "/v6/domain/{d}/zzz-garbage-action-999",
]

BODY = json.dumps(
    {"certId": "probe", "forceHttps": False, "http2Enable": True},
    separators=(",", ":"),
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def qbox_token(path_with_query: str) -> str:
    sig = hmac.new(SK.encode(), (path_with_query + "\n").encode(), hashlib.sha1).digest()
    return f"QBox {AK}:{b64url(sig)}"


def qiniu_token(method, host, path, body):
    date_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sign_str = f"{method.upper()} {path}\nHost: {host}\nContent-Type: application/json\n"
    sign_str += f"X-Qiniu-Date: {date_str}\n\n"
    sign_str += body or ""
    sig = hmac.new(SK.encode(), sign_str.encode(), hashlib.sha1).digest()
    return f"Qiniu {AK}:{b64url(sig)}", date_str


def call(host, path, method, scheme):
    url = f"https://{host}{path}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    data = None
    if method in ("PUT", "POST"):
        data = BODY.encode()
    if scheme == "qbox":
        headers["Authorization"] = qbox_token(path)
    else:
        token, date_str = qiniu_token(method, host, path, BODY if data else None)
        headers["Authorization"] = token
        headers["X-Qiniu-Date"] = date_str

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode()[:200]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]
    except Exception as e:
        return 0, f"network error: {e}"


def verdict(code, text):
    if code in (200, 201):
        return "存在且成功 <<<<<<"
    if code == 612:
        return "存在，但域名不属于该服务"
    if code in (401, 403):
        return "被网关接受（不可信，看对照组的 401）"
    if code == 400:
        return "存在，请求体格式不对"
    if code == 404:
        return "不存在"
    if code == 0:
        return "网络错误"
    return "?"


TASKS = [(p, False) for p in PATHS] + [(p, False) for p in CERT_PATHS] + [(p, True) for p in CONTROL]

results = []
print(f"探测域名: {DOMAIN}")
print("=" * 96)
for host, scheme in HOSTS:
    for p, is_control in TASKS:
        path = p.format(d=DOMAIN, c="certid-probe-0000")
        for method in ("GET", "PUT"):
            # sslize / sslcert 语义上就是写入，没有 GET 形态
            if method == "GET" and path.endswith(("sslize", "sslcert")):
                continue
            code, text = call(host, path, method, scheme)
            v = ("对照组·" if is_control else "") + verdict(code, text)
            tag = "CTRL" if is_control else "    "
            print(f"{tag} {method:4} {host:22} {path:40} [{scheme:5}] -> {code}  {v}", flush=True)
            results.append((code, method, host, path, scheme, v, text, is_control))

print("=" * 96)
print("【结论一】对照组结果（判断 401 是否可信的依据）：")
for r in results:
    if r[7]:
        print(f"  {r[1]:4} {r[2]:22} {r[3]:40} -> {r[0]}  {r[5]}")

print("\n【结论二】排除 404 / 排除对照组后，还活着的端点：")
alive = [r for r in results if r[0] not in (404, 0) and not r[7]]
if not alive:
    print("  全军覆没 —— 七牛确实没有为该域名开放任何 HTTP 换绑接口，只能手动换绑。")
for r in sorted(alive, key=lambda x: x[0]):
    print(f"  {r[1]:4} {r[2]:22} {r[3]:40} [{r[4]:5}] -> {r[0]}  {r[5]}")
    print(f"       响应: {r[6]}")
