#!/usr/bin/env bash
# Remove ONLY the Cait Local Bridge service and its Funnel entry. Leaves other Tailscale/CC/HomeLab services untouched.
set -euo pipefail
LABEL="com.cait.local-bridge"; UID_NUM="$(id -u)"
STATE="${CLB_STATE_DIR:-$HOME/.cait-local-bridge}"
TS="$(command -v tailscale 2>/dev/null || true)"
DIR="$(cd "$(dirname "$0")/.." && pwd)"; PY="$DIR/.venv/bin/python"; cd "$DIR"  # so `bridge` is importable
# Remove ONLY the bridge's own path mounts from the shared :443 Funnel. NEVER `funnel --https=443 off`: that would
# also drop the pre-existing dashboard (/) and gmail (/gmail) mounts.
FUNNEL_PORT="$("$PY" -c "from bridge.config import load_config;print(load_config()['funnel_port'])" 2>/dev/null || echo 443)"
MOUNTS="$("$PY" -c "from bridge.config import load_config;c=load_config();print(' '.join([c['funnel_path'],*c.get('funnel_wellknown_paths',[])]))" 2>/dev/null || echo "/gw /.well-known/oauth-authorization-server /.well-known/openid-configuration /.well-known/oauth-protected-resource")"
if [ -n "$TS" ]; then
  for m in $MOUNTS; do echo "closing Funnel mount :$FUNNEL_PORT$m"; "$TS" funnel --bg --yes --https="$FUNNEL_PORT" --set-path="$m" off 2>/dev/null || true; done
else
  echo "tailscale not found; no Funnel mount removed"
fi
launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/com.cait.local-bridge.plist" "$HOME/bin/bridgectl"
echo "service and Funnel entry removed. State kept at $STATE (delete manually if desired: rm -rf $STATE)."
