#!/usr/bin/env bash
# create_temp_secret.sh - 创建临时凭证文件并在退出时删除
set -euo pipefail
TMPFILE="/tmp/agentbox_secret_$$"
trap 'rm -f "$TMPFILE"' EXIT

echo "creating secret at $TMPFILE"
echo "SUPER_SECRET=$(uuidgen)" > "$TMPFILE"
chmod 600 "$TMPFILE"

# 输出路径，调用方可以把这个路径传给 policy generator 或直接挂载
echo "$TMPFILE"

# 阻塞直到接收到 SIGTERM/SIGINT（演示用途）
while true; do sleep 3600; done
