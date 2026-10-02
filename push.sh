#!/usr/bin/env bash
# 一键推送到 GitHub。先在 GitHub 建好空的私有仓库，再执行本脚本。
set -euo pipefail

REPO="git@github.com:zxwljs/qiniu-cert-automation.git"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$DIR"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "不是 git 仓库，先初始化..."
  git init -b main
  git add -A
  git commit -m "feat: 七牛云 Kodo 域名证书自动续签"
fi

if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REPO"
else
  git remote add origin "$REPO"
fi

echo "推送到 $REPO ..."
git push -u origin main

echo ""
echo "完成。接下来打开仓库页面配置 Secrets："
echo "https://github.com/zxwljs/qiniu-cert-automation/settings/secrets/actions"