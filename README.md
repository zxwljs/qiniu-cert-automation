# 七牛云 Kodo 域名证书自动续签

用 GitHub Actions 当定时器，acme.sh 通过 Cloudflare DNS-01 挑战签发 Let's Encrypt 免费证书，
自动上传到七牛云并换绑到 CDN 加速域名，顺带清理历史遗留的旧证书。

**全程零人工干预，零成本。** 配置完成后除了首次设置，之后再也不需要打开这个仓库。

支持多域名（一张证书覆盖多个加速域名）。

---

## 这项目解决什么问题

七牛云 Kodo 绑定自定义域名后，HTTPS 证书需要自己去管理。而七牛控制台只提供**手动上传**，
没有自动续期能力。Let's Encrypt 证书 90 天就过期，过期后小程序 / App / 微信分享全挂。

网上能搜到的方案基本都是「在服务器上挂 cron」，需要一台常开的机器。
本项目改用 GitHub Actions —— 免费的定时器 + 免费的 runner，不需要任何服务器。

## 为什么不用 Cloudflare Origin CA

七牛官方文档明确写了：

> 自有证书必须是 CA 机构签发；**Cloudflare 平台签发证书只能用于 Cloudflare 平台，
> 无法用于七牛或其他平台**。

虽然有人靠「源站证书 + 拼接 Cloudflare 根证书」硬传成功过（顺序反了会报
`[400338] 获取父级证书失败`），但那属于非官方玩法。

本项目走 Let's Encrypt 公开信任证书，**橙云代理和灰云 DNS only 两种模式都不会报错**。

## 效果

```
[qiniu-sync] 域名: img.example.com
[acme.sh] 证书已跳过, 剩余有效期还有 89 天
[qiniu-sync] 证书指纹与上次同步一致，跳过上传
[qiniu-sync]   [公网验证通过] img.example.com:443  签发机构=Let's Encrypt  到期=Dec 10 08:00:00 2026 GMT
```

真正到期续签时：

```
[acme.sh] Le_Webroot='certs/img.example.com'
[acme-sh] Execute, /root/.acme.sh/acme.sh --install-cert ...
[qiniu-sync] 证书到期时间 2026-12-10 08:00:00, 剩余 89 天
[qiniu-sync] 证书上传成功, certID=627d1a2b3c4d5e6f
[qiniu-sync]   [OK] img.example.com 换绑成功: {"code": 200}
[qiniu-sync] 已删除旧证书 627d0f9e8d7c6b5a (le-img.example.com-20260912) -> {"code": 200}
[qiniu-sync] 旧证书清理完成，删除 1 张，跳过 0 张非本项目证书
[qiniu-sync] 同步完成：1 个域名成功
```

---

## 前置条件

- [ ] 七牛云已完成实名认证
- [ ] Kodo 空间已绑定该加速域名，且域名状态为「已配置」
- [ ] 域名 DNS 托管在 Cloudflare
- [ ] 域名**已完成 ICP 备案**（国内七牛 CDN 强制要求，未备案会报 `400020`）
- [ ] 有 GitHub 账号

## 配置步骤

### 第 1 步 · Fork 本仓库

点右上角 **Fork**。建议设为 **Private**（虽然密钥都存在 Secrets 里不会进代码库，
但万一哪次 commit 失误推到公开仓库，私钥泄露是要出事的）。

### 第 2 步 · 拿 Cloudflare 的 Token

这是最容易卡住的一步，仔细来：

1. Cloudflare 右上角头像 → **My Profile** → **API Tokens** → **Create Token**
2. **使用模板** 选 **Edit zone DNS**
3. **Zone Resources** → Include → **Specific zone** → 选你的域名
4. 点 **Continue to summary** → **Create Token**
5. 复制那串 Token（只显示一次，关掉就看不到了）

顺手记下两个 ID：

| 要找的 | 在哪找 |
|---|---|
| **Account ID** | Cloudflare 主页（选域名之前那个页面）右侧栏 |
| **Zone ID** | 进入你的域名后，Overview 页右侧栏 |

### 第 3 步 · 拿七牛的密钥

七牛控制台 → 右上角头像 → **密钥管理** → 复制 **AccessKey** 和 **SecretKey**。

> 建议单独创建一个只用于本项目的子账号密钥，权限只勾 CDN / 域名管理 / 证书管理。
> 主账号密钥权限太大，泄露代价高。

### 第 4 步 · 添加 Secrets

进入你 Fork 后的仓库 → **Settings** → **Secrets and variables** → **Actions**
→ **New repository secret**，逐个添加：

| Secret 名 | 值 | 必填 |
|---|---|---|
| `QINIU_AK` | 七牛云 AccessKey | ✅ |
| `QINIU_SK` | 七牛云 SecretKey | ✅ |
| `QINIU_DOMAIN` | 七牛加速域名。多个用英文逗号分隔，如 `img.example.com,static.example.com`。**不要带 `https://`** | ✅ |
| `CF_API_TOKEN` | 第 2 步创建的 Token | ✅ |
| `CF_ACCOUNT_ID` | Cloudflare Account ID | ✅ |
| `CF_ZONE_ID` | 该域名的 Zone ID | ✅ |
| `ACME_EMAIL` | 接收证书到期通知的邮箱 | ✅ |
| `FORCE_HTTPS` | 填 `1` 表示把 HTTP 301 跳转到 HTTPS；留空或填 `0` 则保留 HTTP 访问 | ❌ |

> 多个域名必须都在同一个 Cloudflare Zone 下，否则 `CF_ZONE_ID` 只对其中一个生效，
> 其它域名会签发失败。

### 第 5 步 · 跑一次验证

**Actions** 标签页 → 左侧选 **Auto Renew SSL for Qiniu Kodo** → 右上 **Run workflow** →
勾选 `force_renew` → 点绿色按钮。

第一次会签发新证书并同步。成功后去七牛控制台确认证书已换绑，
然后浏览器访问 `https://你的域名/` 确认能正常打开。

### 第 6 步 · 交给定时器

之后每天 UTC 03:17（北京时间 11:17）自动检查一次。收工。

---

## 常见问题

### 日志里显示「跳过」，是失败了吗

不是。acme.sh 只在证书剩余有效期不足 30 天时才真正续签，平时就是「跳过」。
**这说明一切正常。**

### 报 `too many certificates already issued`

Let's Encrypt 的速率限制触发了（同一域名每周 50 次）。

几乎一定是 `actions/cache` 那一步被删掉或没生效了 —— 每次运行都重新签发，一周就超。
检查缓存路径里是否包含 `~/.acme.sh` 和 `certs`。

已经触发限制的话，等一周自动恢复，或临时用 Let's Encrypt 的测试环境验证流程。

### 报 `404` / `Repository not found`

这个概率只出现在 Fork 后。检查 **Settings** → **Actions** → **General** →
**Workflow permissions** 是否允许 Actions 运行。

### 上传证书报 `[400338] 获取父级证书失败`

本项目走 Let's Encrypt，不该出现这个错。如果出现了，说明有人手动改成了
Cloudflare Origin CA 证书 —— 那个需要拼 Cloudflare 根证书，且**顺序必须是服务器证书在前**。

### 换绑七牛域名失败

脚本会区分对待：

- **所有域名都失败** → 脚本以非零退出码结束，日志里是 `[FAIL]`。常见原因是域名未备案
  （`400020`）或域名没在七牛绑定过
- **部分域名失败** → 其余正常生效，日志汇总里会写「N 个成功，M 个失败」

### 换了 IP / 换了服务器，还需要重新配置吗

不需要。IP 变化不影响本项目 —— 它只跟域名和 DNS 有关。

## 原理

```
GitHub Actions（每天定时）
  └─ acme.sh --issue --dns dns_cf        ← Cloudflare DNS-01 挑战，自动写 TXT 记录
       └─ Let's Encrypt 免费证书（90 天）
            └─ qiniu-cert-sync.py
                 ├─ POST   fusion.qiniuapi.com/sslcert          上传证书
                 ├─ PUT    api.qiniu.com/domain/{d}/httpsconf   换绑到各域名
                 ├─ DELETE fusion.qiniuapi.com/sslcert/{id}     清理旧证书
                 └─ 直连 443 验证证书真的生效
```

## 实现要点

给二次开发者的几条注意事项，改动前请先读：

**七牛有两套鉴权，混用会一直 401。** 这是本项目最容易踩的坑：

| 接口 | 域名 | 鉴权方式 |
|---|---|---|
| 证书上传 / 列表 / 删除 | `fusion.qiniuapi.com` | **QBox**：签名字符串 = `路径(含query) + "\n"`，不含域名 |
| 域名 HTTPS 配置 | `api.qiniu.com` | **Qiniu**：签名字段串，必须配合 `X-Qiniu-Date` 请求头 |

**`actions/cache` 那一步绝对不能删。** 见上面的速率限制问题。

**七牛要求证书剩余有效期 ≥ 30 天**，不足会直接拒收。脚本在上传前主动检查并退出，
而不是让接口返回一个难懂的错误码。

**`ca` 字段必须传完整证书链**（`fullchain.pem`），不是只传站点证书，
否则部分客户端会报证书不信任。

**七牛 API 成功时的 `code` 字段可能是 `200` 也可能是 `0`**，判断时要都放过。

**清理旧证书只删名字以 `le-` 开头的**，绝不碰你手动上传的证书。

## 本地调试

不用等定时器，本地就能复现。注意不要把 AK/SK 写进代码或提交到仓库：

```bash
export QINIU_AK=xxx
export QINIU_SK=yyy
export QINIU_DOMAIN=img.example.com
export CERT_DIR=./certs/img.example.com   # 需含 fullchain.pem / privkey.pem
export FORCE_HTTPS=1

python3 scripts/qiniu-cert-sync.py
```

加 `FORCE_UPLOAD=1` 可以跳过证书指纹去重，强制重传，方便验证换绑是否真的生效。

## 目录结构

```
.github/workflows/renew-ssl.yml   # 定时任务定义
scripts/qiniu-cert-sync.py        # 上传 / 换绑 / 清理，纯标准库无需 pip
```

## 安全须知

- 仓库设为 **Private**
- Secrets 只在 GitHub Actions 里配置，**永远不要写进 workflow 文件或代码**
- `QINIU_SK` 用子账号密钥，权限最小化
- `.gitignore` 已排除 `*.pem` / `*.key`，别手动改掉它

## License

MIT