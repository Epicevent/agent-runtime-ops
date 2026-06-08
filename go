#!/usr/bin/env bash
set -euo pipefail

REF="${1:-${AGENT_RUNTIME_OPS_REF:-}}"
if [[ ! "$REF" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: first install requires a full 40-character commit sha" >&2
  echo "usage: curl -fsSL https://raw.githubusercontent.com/Epicevent/agent-runtime-ops/COMMIT/go | sudo bash -s -- COMMIT" >&2
  exit 2
fi

export AGENT_RUNTIME_OPS_REF="$REF"
URL="${AGENT_RUNTIME_OPS_INSTALL_URL:-https://raw.githubusercontent.com/Epicevent/agent-runtime-ops/$REF/install.sh}"
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
