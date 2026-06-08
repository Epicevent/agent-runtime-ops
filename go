#!/usr/bin/env bash
set -euo pipefail

URL="${AGENT_RUNTIME_OPS_INSTALL_URL:-https://raw.github.com/Epicevent/agent-runtime-ops/main/install.sh}"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" | bash
elif command -v wget >/dev/null 2>&1; then
  wget -qO- "$URL" | bash
else
  echo "error: curl or wget is required" >&2
  exit 1
fi
