#!/usr/bin/env bash
set -euo pipefail

URL="${AGENT_RUNTIME_OPS_INSTALL_URL:-https://raw.githubusercontent.com/Epicevent/agent-runtime-ops/main/install.sh}"
FETCH_URL="$URL"
if [[ "$FETCH_URL" != *\?* ]]; then
  FETCH_URL="${FETCH_URL}?ts=$(date +%s)"
fi

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$FETCH_URL" | bash
elif command -v wget >/dev/null 2>&1; then
  wget -qO- "$FETCH_URL" | bash
else
  echo "error: curl or wget is required" >&2
  exit 1
fi
