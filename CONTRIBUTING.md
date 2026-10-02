# 贡献指南

感谢参与。这个项目很小，欢迎各种改进。

## 可以贡献什么

- **支持更多 DNS 服务商** —— 目前只做了 Cloudflare（`dns_cf`）。DNSPod、阿里云、腾讯云、
  GoDaddy 等都可以加，换 acme.sh 的插件参数即可
- **支持七牛源站域名与 CDN 域名区分配置** —— 目前两者用同一套 HTTPS 配置
- **证书到期前的通知** —— 接 webhook、邮件、钉钉 / 飞书 / 企业微信机器人
- **改成 Cloudflare 定时触发** —— 配合 Cloudflare Workers 也能做，不一定要用 Actions
- **补充文档和踩坑记录** —— 尤其是报错排查部分

## 提交前务必确认

改动脚本后，本地跑一遍校验：

```bash
# 1. 语法与 import 完整性
python3 -c "import ast; ast.parse(open('scripts/qiniu-cert-sync.py',encoding='utf-8').read()); print('语法 OK')"

# 2. 模块能真正加载（能抓出漏掉的 import）
python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('m','scripts/qiniu-cert-sync.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print('加载 OK')
"

# 3. workflow YAML 能解析
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/renew-ssl.yml',encoding='utf-8')); print('YAML OK')"
```

**改 workflow 后请务必跑第 3 条。** YAML 缩进或字符写错（比如 `- key` 打成 `- name`）
不会在本地报错，但推上去之后 GitHub 直接解析失败，工作流整个不运行。

## 不要做的事

- ❌ 把任何真实密钥、token、域名写进代码或 workflow 文件
- ❌ 删除 `actions/cache` 那一步（会导致 Let's Encrypt 速率限制）
- ❌ 改动 `cleanup_old_certs` 里 `le-` 前缀的判断（会误删用户手动上传的证书）
- ❌ 放宽 `check_expiry` 的 30 天下限（七牛硬性要求，不够会直接拒收）
- ❌ 在workflow 里 `source ~/.acme.sh/acme.sh` 然后调裸 `acme.sh` 命令

## 几个已踩过的坑

**GitHub Actions 每个 step 都是独立 shell，不加载 `~/.bashrc`。**
acme.sh 安装器只把别名写进 bashrc，所以 `acme.sh --xxx` 必然 `command not found`（exit 127）。
正确做法是 `ACME="$HOME/.acme.sh/acme.sh"` + `"$ACME" --xxx`。
而且 `source` 那个脚本本身就会执行整个 acme.sh（打印一大堆帮助信息），
用绝对路径调用同时也避免了这个问题。

**`set -euo pipefail` 环境下变量必须先赋值再用。**
`ACME=...` 要写在 `set -e` 之后、`"$ACME"` 首次引用之前，否则 unbound variable 会直接中断。

**不要给七牛的 `httpsconf` 接口传 `tlsVersions`。**
文档写它是 `string`，但后端 Go 结构体是 `[]fusion.TlsVersion`，传字符串直接400。
这是文档与实现不一致，不是我们的 bug。它是选填项，省掉即可。

**`api.qiniu.com` 和 `api.qiniuapi.com` 是两个产品，不是一个东西。**
前者是 **CDN**，后者是 **Kodo 存储**（七牛官方仓库 `qiniu/hadoop-kodo` 的区域配置里
写着 `apiHost: api.qiniuapi.com`）。两者域名只差一个后缀，但源站域名打到 CDN 主机上
只会得到 `612 no such domain`。而且鉴权也不同：Kodo 走 **QBox**，CDN 走 **Qiniu**。

**别用假凭据探测来判断接口存不存在，401 是假的。**
`api.qiniu.com` 上有 `/domain/{域名}/{任意动作}` 的通配路由，会**先鉴权再判断动作**，
实测连 `/domain/xxx/zzz-garbage-action-999` 都返回 401。所以 401 只代表"域名这一级匹配上了"。
真正能区分的是**用真凭据**打：`612` = 接口存在但域名不属于该产品，`404` = 接口不存在。
`scripts/probe-qiniu-api.py` 里内置了对照组，就是为了自动识别这种假象。

## 提交信息

用中文或英文都可以，说清楚改了什么、为什么。类型参考：

- `feat:` 新功能
- `fix:` 修 bug
- `docs:` 只改文档
- `chore:` 杂项（依赖、配置）

## 提问

遇到问题开 Issue，附上：

1. 你的 workflow 完整日志（**注意删掉域名和密钥**）
2. 报错的具体行
3. 你的 DNS 托管商和七牛空间所在区域