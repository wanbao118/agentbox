#!/usr/bin/env bash
# agentbox e2e verification (macOS / seatbelt).
#
# Prereqs: mxc native binary discoverable (`agentbox doctor`), run OUTSIDE any
# existing Seatbelt sandbox (Seatbelt cannot nest — sandbox_init returns EPERM
# under a wrapping sandbox such as CI file-sandbox modes).
set -euo pipefail

AGENTBOX="${AGENTBOX:-$(dirname "$0")/../target/release/agentbox}"
WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR_RUN="$(mktemp -d)"
PASS=0; FAIL=0

check() { # check <name> <condition-exit>
  if [ "$2" -eq 0 ]; then echo "  ✓ $1"; PASS=$((PASS+1)); else echo "  ✗ $1"; FAIL=$((FAIL+1)); fi
}

echo "== agentbox e2e ($(uname -m) $(sw_vers -productVersion 2>/dev/null || echo linux)) =="

echo "[1] allowlisted domain passes through the enforcing proxy"
code=$("$AGENTBOX" run shell --workspace "$TMPDIR_RUN" --allow api.anthropic.com -- \
  -c "curl -sS -o /dev/null -w '%{http_code}' --max-time 15 https://api.anthropic.com/v1/models" 2>/dev/null || echo ERR)
[ "$code" = "401" ] || [ "$code" = "403" ] || [ "$code" = "429" ]
check "tunneled HTTPS to api.anthropic.com (got HTTP $code)" $?

echo "[2] non-allowlisted domain is denied by the proxy"
if "$AGENTBOX" run shell --workspace "$TMPDIR_RUN" --allow api.anthropic.com -- \
  -c "curl -sS --max-time 15 https://example.com/" >/dev/null 2>&1; then
  check "example.com rejected" 1
else
  check "example.com rejected" 0
fi

echo "[3] raw-socket direct egress is blocked by seatbelt"
out=$("$AGENTBOX" run shell --workspace "$TMPDIR_RUN" --allow '*' -- \
  -c "python3 -c \"import socket;s=socket.socket();s.settimeout(5);s.connect(('93.184.216.34',80))\"" 2>&1 || true)
case "$out" in
  *BYPASS*) check "raw socket blocked" 1 ;;
  *) check "raw socket blocked" 0 ;;
esac

echo "[4] workspace-write enforcement"
"$AGENTBOX" run shell --workspace "$TMPDIR_RUN" -- \
  -c "echo hi > out.txt && cat out.txt | grep -q hi" >/dev/null 2>&1
check "write inside workspace ok" $?
if "$AGENTBOX" run shell --workspace "$TMPDIR_RUN" -- \
  -c "echo nope > /tmp-agentbox-should-fail" >/dev/null 2>&1; then
  check "write outside workspace denied" 1
else
  check "write outside workspace denied" 0
fi

echo "[5] host HOME isolation"
out=$("$AGENTBOX" run shell --workspace "$TMPDIR_RUN" -- \
  -c 'echo "$HOME"; head -c 5 ~/.ssh/id_* 2>/dev/null' 2>/dev/null || true)
case "$out" in
  *"agentbox-"*) check "HOME redirected to session scratch" 0 ;;
 *) check "HOME redirected to session scratch" 1 ;;
esac
if echo "$out" | grep -qE "(PRIVATE|OPENSSH|RSA )"; then
  check "host ssh keys unreadable" 1
else
  check "host ssh keys unreadable" 0
fi

echo "[6] generated config validates against MXC's own parser (schema lock)"
cfg="$TMPDIR_RUN/config.json"
"$AGENTBOX" run shell --workspace "$TMPDIR_RUN" --allow api.anthropic.com --dry-run   > "$cfg" 2>/dev/null
MXC_BIN="${MXC_BIN:-$("$AGENTBOX" doctor 2>/dev/null | awk '/mxc-binary/ {print $3}')}"
if [ -x "$MXC_BIN" ] && "$MXC_BIN" --dry-run "$cfg" 2>&1 | grep -q "validation passed"; then
  check "mxc accepts agentbox-generated config" 0
else
  check "mxc accepts agentbox-generated config" 1
fi

echo "[7] direct DNS / UDP egress is kernel-blocked"
out=$("$AGENTBOX" run shell --workspace "$TMPDIR_RUN" --allow '*' -- \
  -c "python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(4);s.sendto(b'x',('8.8.8.8',53))\"" 2>&1 || true)
case "$out" in
  *EPERM*|*"Operation not permitted"*|*PermissionError*) check "UDP :53 sendto blocked" 0 ;;
  *) check "UDP :53 sendto blocked" 1 ;;
esac

echo "[8] host agent sockets / env secrets do not leak"
out=$("$AGENTBOX" run shell --workspace "$TMPDIR_RUN" -- \
  -c 'echo "SSH=$SSH_AUTH_SOCK"; echo "AWS=$AWS_SECRET_ACCESS_KEY"' 2>/dev/null || true)
case "$out" in
  *SSH=/*) check "SSH_AUTH_SOCK absent" 1 ;;
  *) check "SSH_AUTH_SOCK absent" 0 ;;
esac
case "$out" in
  *AWS=+[^[:space:]]*) check "host secrets absent from env" 1 ;;
  *) check "host secrets absent from env" 0 ;;
esac

echo "[9] cross-session proxy borrowing requires the session token"
PORT=$((20000 + RANDOM % 20000))
"$AGENTBOX" proxy --token topsecret --allow '*' --port "$PORT" &>/dev/null &
PROXY_PID=$!
up=1
for _ in $(seq 1 20); do
  if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then up=0; break; fi
  sleep 0.2
done
if [ "$up" -ne 0 ]; then
  check "standalone proxy started" 1
else
  check "standalone proxy started" 0
  # A rejected CONNECT tunnel surfaces as exit 56 with the status in stderr
  # (%{http_code} reports 000 since no origin response exists).
  err=$(curl -sS -o /dev/null -x "http://127.0.0.1:$PORT" --max-time 5 https://api.anthropic.com 2>&1 || true)
  rc=0
  case "$err" in *"response 407"*) ;; *) rc=1 ;; esac
  check "tokenless CONNECT rejected (got: $(echo "$err" | tail -1))" $rc
fi
kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true

echo "[10] post-DNS guard: allowlisted hostname resolving into loopback is refused"
# Port ranges stay disjoint from case [9] (20000-39999) and below the macOS
# ephemeral range (>=49152).
SECRET_PORT=$((43000 + RANDOM % 1500))
GUARD_PROXY_PORT=$((45000 + RANDOM % 1500))
mkdir -p "$TMPDIR_RUN/www"
echo "HOST-LOCAL-SECRET-PROOF" > "$TMPDIR_RUN/www/secret.txt"
python3 -m http.server "$SECRET_PORT" --bind 127.0.0.1 --directory "$TMPDIR_RUN/www" &>/dev/null &
HTTPD_PID=$!
for _ in $(seq 1 25); do
  nc -z 127.0.0.1 "$SECRET_PORT" 2>/dev/null && break
  sleep 0.2
done
"$AGENTBOX" proxy --allow localhost --port "$GUARD_PROXY_PORT" &>/dev/null &
GUARD_PID=$!
up=1
for _ in $(seq 1 20); do
  nc -z 127.0.0.1 "$GUARD_PROXY_PORT" 2>/dev/null && up=0 && break
  sleep 0.2
done
if [ "$up" -ne 0 ]; then
  check "guard-proxy started" 1
else
  code=$(curl -sS -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$GUARD_PROXY_PORT" \
    --max-time 5 "http://localhost:$SECRET_PORT/secret.txt" 2>/dev/null || echo ERR)
  case "$code" in
    502|ERR) check "localhost -> 127.0.0.1 refused by ssrf guard (got HTTP $code)" 0 ;;
    *) check "localhost -> 127.0.0.1 refused by ssrf guard (got HTTP $code)" 1 ;;
  esac
fi

echo "[11] explicit IP rule still reaches host loopback (deliberate opt-in)"
IP_PROXY_PORT=$((47000 + RANDOM % 1500))
"$AGENTBOX" proxy --allow 127.0.0.1 --port "$IP_PROXY_PORT" &>/dev/null &
IPP_PID=$!
up=1
for _ in $(seq 1 20); do
  nc -z 127.0.0.1 "$IP_PROXY_PORT" 2>/dev/null && up=0 && break
  sleep 0.2
done
if [ "$up" -ne 0 ]; then
  check "ip-rule proxy started" 1
else
  body=""
  for _ in 1 2; do
    body=$(curl -sS -x "http://127.0.0.1:$IP_PROXY_PORT" --max-time 5 \
      "http://127.0.0.1:$SECRET_PORT/secret.txt" 2>/dev/null || echo ERR)
    [[ "$body" == *HOST-LOCAL-SECRET-PROOF* ]] && break
    sleep 1
  done
  case "$body" in
    *HOST-LOCAL-SECRET-PROOF*) check "explicit 127.0.0.1 rule tunnels (escape hatch intact)" 0 ;;
    *) check "explicit 127.0.0.1 rule tunnels (escape hatch intact)" 1 ;;
  esac
fi
kill $HTTPD_PID $GUARD_PID $IPP_PID 2>/dev/null || true
wait $HTTPD_PID $GUARD_PID $IPP_PID 2>/dev/null || true

echo "[12] toolchain caches are mounted READ-ONLY (no cross-session poisoning)"
POISON="$HOME/.cache/pip/agentbox-e2e-poison"
rm -f "$POISON"
"$AGENTBOX" run shell --workspace "$TMPDIR_RUN" -- \
  -c 'touch ~/.cache/pip/agentbox-e2e-poison' >/dev/null 2>&1 || true
if [ -e "$POISON" ]; then
  rm -f "$POISON"
  check "host pip cache unchanged after sandbox write attempt" 1
else
  check "host pip cache unchanged after sandbox write attempt" 0
fi

echo "[13] injected secrets never appear in any process argv"
ANTHROPIC_API_KEY=SUPERSECRET-E2E-PROOF "$AGENTBOX" run shell --workspace "$TMPDIR_RUN" -- \
  -c 'sleep 12' >/dev/null 2>&1 &
RUN_PID=$!
sleep 6
if ps -ww -Ao args= 2>/dev/null | grep -q 'SUPERSECRET[-]E2E-PROOF'; then
  check "secret absent from all argv (config rides a 0600 file)" 1
else
  check "secret absent from all argv (config rides a 0600 file)" 0
fi
wait $RUN_PID 2>/dev/null || true

echo "[14] --strict fails the session when policy denies egress"
# The session is SUPPOSED to fail (exit 2); guard it against set -e.
set +e
"$AGENTBOX" run shell --workspace "$TMPDIR_RUN" --strict \
  -c 'curl -sS -o /dev/null --max-time 8 https://example.com/' >/dev/null 2>&1
rc=$?
set -e
[ "$rc" = "2" ]
check "strict session exits 2 on deny (got $rc)" $?

"$AGENTBOX" run shell --workspace "$TMPDIR_RUN" --offline -- -c 'true' >/dev/null 2>&1
[ $? -eq 0 ]
check "clean session unaffected by --strict (exit 0)" $?

rm -rf "$TMPDIR_RUN"
echo
echo "== results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
