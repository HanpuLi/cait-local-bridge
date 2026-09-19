#!/usr/bin/env bash
# Remove only ScopeRail's service and Funnel mounts. Leave unrelated Tailscale/HomeLab services untouched.
set -euo pipefail
LABEL="io.github.hanpuli.scoperail"
LEGACY_LABEL="com.cait.local-bridge"
UID_NUM="$(id -u)"
LEGACY_STATE="$HOME/.cait-local-bridge"
DEFAULT_STATE="$HOME/.scoperail"
if [ -d "$LEGACY_STATE" ] && [ ! -e "$DEFAULT_STATE" ]; then DEFAULT_STATE="$LEGACY_STATE"; fi
STATE="${SCOPERAIL_STATE_DIR:-${CLB_STATE_DIR:-$DEFAULT_STATE}}"
TS="$(command -v tailscale 2>/dev/null || true)"
DIR="$(cd "$(dirname "$0")/.." && pwd)"; PY="$DIR/.venv/bin/python"; cd "$DIR"
FUNNEL_PORT="$("$PY" -c "from bridge.config import load_config;print(load_config()['funnel_port'])" 2>/dev/null || echo 443)"
MOUNTS="$("$PY" -c "from bridge.config import load_config;c=load_config();print(' '.join([c['funnel_path'],*c.get('funnel_wellknown_paths',[])]))" 2>/dev/null || echo "/gw /.well-known/oauth-authorization-server /.well-known/openid-configuration /.well-known/oauth-protected-resource")"
if [ -n "$TS" ]; then
  for m in $MOUNTS; do
    echo "closing Funnel mount :$FUNNEL_PORT$m"
    "$TS" funnel --bg --yes --https="$FUNNEL_PORT" --set-path="$m" off 2>/dev/null || true
  done
else
  echo "tailscale not found; no Funnel mount removed"
fi
launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
launchctl bootout "gui/$UID_NUM/$LEGACY_LABEL" 2>/dev/null || true
rm -f   "$HOME/Library/LaunchAgents/io.github.hanpuli.scoperail.plist"   "$HOME/Library/LaunchAgents/com.cait.local-bridge.plist"   "$HOME/bin/scoperailctl" "$HOME/bin/bridgectl"
echo "service and Funnel entry removed. State kept at $STATE (delete manually if desired)."
