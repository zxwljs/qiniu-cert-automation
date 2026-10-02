# 七牛云 Kodo 域名证书自动续签（GitHub Actions + Cloudflare）

用 GitHub Actions 当定时器，acme.sh 通过 Cloudflare DNS-01 挑战签发 Let's Encrypt 免费证书，
自动上传到七牛云并换绑到 CDN 加速域名，顺带清理旧证书。全程零人工干预，零成本。

## 为什么不用 Cloudflare Origin CA

七牛官方明确写了：**Cloudflare 平台签发证书只能用于 Cloudflare 平台，无法用于七牛或其他平台**。
虽然有人靠"源站证书 + Cloudflare 根证书"拼接绕过去上传成功（能传，但属于非官方玩法，
且 Origin CA 最长 15 年不续期反而让这套自动化失去意义），所以本方案走 Let's Encrypt 公开信任证书，
灰云/橙云两种模式都不会报错。

## 前置条件

- 七牛云已完成实名认证，Kodo 空间已绑定该加速域名
- 域名 DNS 托管在 Cloudflare
- 域名**已完成 ICP 备案**（国内七牛 CDN 强制要求）

## 配置步骤

### 1. 先建仓库

把本目录推到任意 GitHub 仓库（新建一个即可，设为 private 更安全）。

### 2. 七牛云取密钥

七牛控制台 → 个人中心 → 密钥管理 → 得到 `AccessKey` / `SecretKey`。

### 3. Cloudflare 取 Token

Cloudflare → My Profile → API Tokens → Create Token：

- 权限：`Zone / DNS / Edit`（DNS-01 挑战要写 TXT 记录）
- Zone Resources：Include → Specific zone → 选你的域名

再从 **Cloudflare 主页 Overview 页右侧复制 Account ID**；
Zone ID 在域名 Overview 页右侧。

### 4. 在 GitHub 仓库添加 Secrets

Settings → Secrets and variables → Actions → New repository secret，逐个添加：

| Secret 名 | 值 |
|---|---|
| `QINIU_AK` | 七牛云 AccessKey |
| `QINIU_SK` | 七牛云 SecretKey |
| `QINIU_DOMAIN` | 要绑定的加速域名，如 `img.example.com`（只填域名，不要 https://） |
| `CF_API_TOKEN` | 上一步创建的 Token |
| `CF_ACCOUNT_ID` | Cloudflare Account ID |
| `CF_ZONE_ID` | 该域名的 Zone ID |
| `ACME_EMAIL` | 证书到期通知邮箱，如 `you@example.com` |
| `FORCE_HTTPS` | 填 `1` 表示把 HTTP 301 跳转到 HTTPS；不填或填 `0` 则保留 HTTP |

### 5. 手动跑一次验证

Actions 标签页 → `Auto Renew SSL for Qiniu Kodo` → **Run workflow**。

第一次会签发新证书并同步。成功后去七牛控制台确认证书已换绑，且访问
`https://你的域名/` 能正常打开。

### 6. 收工

之后每天 UTC 03:17（北京时间 11:17）自动检查一次。acme.sh 在证书剩余 30 天时才真正续签，
所以你不会看到每次都产生新证书——**这是正常的**。续签后会自动上传七牛并清理旧证书。

## 目录说明

```
.github/workflows/renew-ssl.yml   # 定时任务定义
scripts/qiniu-cert-sync.py        # 上传/换绑/清理，纯标准库无需 pip
```

## 关键实现说明

### 两套鉴权不能混用

七牛有两套签名机制，脚本里分别实现，写错会一直 401：

- **QBox**（`fusion.qiniuapi.com`）：证书上传/列表/删除。签名串是 `路径(含query) + "\n"`，不带域名
- **Qiniu**（`api.qiniu.com`）：域名 HTTPS 配置。签名字段串必须配合 `X-Qiniu-Date` 请求头一起返回

### 缓存必须有

工作流里的 `actions/cache` 是关键。**没有缓存的话每次运行都会重新签发**，
很快触发 Let's Encrypt 的速率限制（同一域名每周 50 次）然后被锁。
缓存路径同时包含 `~/.acme.sh`（账户密钥）和 `certs/`（证书与状态文件）。

### 三个容易踩的坑

1. **证书剩余有效期必须 ≥ 30 天**，七牛会拒收。脚本在上传前会主动检查并退出。
2. **CA 字段要传完整证书链**（`fullchain.pem`），不是只传站点证书，否则部分客户端报不信任。
3. **证书链顺序**：服务器证书在前，中间证书在后。七牛上传 CF Origin CA 时报的
   `[400338] 获取父级证书失败` 就是顺序反了导致的。

### 手动排查命令

在 Actions 日志里看到失败，可以本地用 Python 直接复现（注意：不要把 AK/SK 提交到仓库）：

```bash
export QINIU_AK=xxx QINIU_SK=yyy QINIU_DOMAIN=img.example.com
export CERT_DIR=./certs/img.example.com
python3 scripts/qiniu-cert-sync.py
```

加 `FORCE_UPLOAD=1` 可以跳过指纹去重强制重传，方便验证换绑是否真的生效。

## 关于 Orange Cloud 的一个提醒

如果你的加速域名在 Cloudflare 里是**橙云代理**，那么：

- 浏览器侧证书由 Cloudflare 边缘自动续期，不用管
- 但七牛侧仍然需要一张证书（回源用），也就是本方案在做的事

如果改成 **Cloudflare Origin CA**，理论上可以一劳永逸，但七牛官方不支持，
所以本方案不采用。若你确实想走 Origin CA 路线，需要自己拼 Cloudflare 根证书，
七牛侧可能返回 `[400338]`。

## 别做的事

- ❌ 把 `QINIU_SK` 写进 workflow 文件（必须是 Secrets）
- ❌ 给七牛 SecretKey 开启过多权限（只保留 CDN / 域名管理 / 证书管理即可）
- ❌ 把 `CF_API_TOKEN` 换成 Global API Key（明文形式容易泄露，Token 可随时吊销）