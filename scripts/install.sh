#!/usr/bin/env bash
# agentbox installer — builds and installs the CLI plus its mxc dependency.
#
#   ./scripts/install.sh
#
# Layout after install:
#   ~/.cargo/bin/agentbox        the CLI (cargo install)
#   ~/.agentbox/bin/mxc-*        MXC native binary (discovered or built here)
#
# The CLI finds mxc via AGENTBOX_MXC_BIN, PATH, or ~/.agentbox/bin. A sibling
# mxc source checkout is only trusted when explicitly opted in with
# AGENTBOX_ALLOW_SIBLING_MXC=1 (a repo you clone can plant an executable at
# that plausible-looking path — the sandbox launcher must not come from there
# unless YOU put it there). This script guarantees one of the trust roots.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST_BIN="$HOME/.agentbox/bin"
OS="$(uname -s)"
mkdir -p "$DEST_BIN"

log() { echo "agentbox-install: $*"; }

# ---------------------------------------------------------------------------
# 1. Build + install the CLI.
# ---------------------------------------------------------------------------
log "building agentbox (release)..."
(cd "$ROOT" && cargo build --release)

log "installing CLI to ~/.cargo/bin (cargo install)"
(cd "$ROOT" && cargo install --path crates/ab-cli --force >/dev/null)

# ---------------------------------------------------------------------------
# 2. Provision the platform mxc native binary into ~/.agentbox/bin.
# ---------------------------------------------------------------------------
case "$OS" in
  Darwin) MXC_NAME="mxc-exec-mac" ;;
  Linux)  MXC_NAME="lxc-exec" ;;
  *) log "unsupported OS '$OS' (macOS/Linux only in v1)"; exit 1 ;;
esac

have_mxc() { [ -x "$1" ] && [ -f "$1" ]; }

copy_if_exec() { # <candidate>
  if have_mxc "$1"; then
    cp "$1" "$DEST_BIN/$MXC_NAME"
    log "installed $(basename "$1") -> $DEST_BIN/$MXC_NAME"
    return 0
  fi
  return 1
}

mxc_installed() { have_mxc "$DEST_BIN/$MXC_NAME"; }

# a) already installed?
if mxc_installed; then
  log "mxc binary already present at $DEST_BIN/$MXC_NAME"
fi

# b) explicit override
if ! mxc_installed && [ -n "${AGENTBOX_MXC_BIN:-}" ]; then
  copy_if_exec "$AGENTBOX_MXC_BIN" || true
fi

# c) sibling source checkout — opt-in only (AGENTBOX_ALLOW_SIBLING_MXC=1):
#    a repo you clone can plant an executable at this plausible-looking path,
#    and that binary would run unsandboxed on the host as the sandbox launcher.
if ! mxc_installed && [ "${AGENTBOX_ALLOW_SIBLING_MXC:-0}" = "1" ]; then
  d="$ROOT"
  while [ "$d" != "/" ]; do
    for c in \
      "$d/mxc/src/target/$([ "$(uname -m)" = arm64 ] && echo aarch64 || echo x86_64)-apple-darwin/release/$MXC_NAME" \
      "$d/mxc/src/target/release/$MXC_NAME" \
      "$d/mxc/sdk/node/bin/$([ "$(uname -m)" = arm64 ] && echo arm64 || echo x64)/$MXC_NAME"; do
      if copy_if_exec "$c"; then break 2; fi
    done
    d="$(dirname "$d")"
  done
fi

# d) npm-installed SDK prebuilt binaries
if ! mxc_installed && command -v npm >/dev/null 2>&1; then
  NPM_ROOT="$(npm root -g 2>/dev/null || true)"
  ARCH_DIR=$([ "$(uname -m)" = arm64 ] && echo arm64 || echo x64)
  if [ -n "$NPM_ROOT" ]; then
    copy_if_exec "$NPM_ROOT/@microsoft/mxc-sdk/bin/$ARCH_DIR/$MXC_NAME" || true
  fi
fi

# e) last resort: build from a sibling checkout — same opt-in gate as (c)
if ! mxc_installed && [ "${AGENTBOX_ALLOW_SIBLING_MXC:-0}" = "1" ]; then
  d="$ROOT"
  while [ "$d" != "/" ]; do
    if [ -d "$d/mxc/src" ]; then
      log "building sibling mxc checkout at $d/mxc (one-time, several minutes)..."
      if [ "$OS" = Darwin ]; then
        (cd "$d/mxc" && bash build-mac.sh --rust-only >/dev/null)
      else
        (cd "$d/mxc" && bash build.sh --rust-only >/dev/null)
      fi
      copy_if_exec "$d/mxc/src/target/*/release/$MXC_NAME" 2>/dev/null || true
      break
    fi
    d="$(dirname "$d")"
  done
fi

if ! mxc_installed; then
  log "WARNING: no mxc binary found."
  log "  Install it manually, e.g.:  npm i -g @microsoft/mxc-sdk"
  log "  then re-run this script, or set AGENTBOX_MXC_BIN to the binary path."
  log "  A sibling ./mxc source checkout is only used when you explicitly set"
  log "  AGENTBOX_ALLOW_SIBLING_MXC=1 (trust that checkout)."
  exit 2
fi

# ---------------------------------------------------------------------------
# 3. Verify.
# ---------------------------------------------------------------------------
log "done. verifying:"
"$HOME/.cargo/bin/agentbox" doctor || true
echo
echo "agentbox-install: ready — try:  agentbox run shell -- -c 'echo hi'"
