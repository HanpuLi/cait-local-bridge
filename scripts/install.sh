#!/usr/bin/env bash
# Install ScopeRail as a launchd user service independent of any Claude Code / Codex session.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
LEGACY_STATE="$HOME/.cait-local-bridge"
DEFAULT_STATE="$HOME/.scoperail"
if [ -d "$LEGACY_STATE" ] && [ ! -e "$DEFAULT_STATE" ]; then
  DEFAULT_STATE="$LEGACY_STATE"
fi
STATE="${SCOPERAIL_STATE_DIR:-${CLB_STATE_DIR:-$DEFAULT_STATE}}"
PLIST="$HOME/Library/LaunchAgents/io.github.hanpuli.scoperail.plist"
LEGACY_PLIST="$HOME/Library/LaunchAgents/com.cait.local-bridge.plist"
LABEL="io.github.hanpuli.scoperail"
LEGACY_LABEL="com.cait.local-bridge"
PY="$DIR/.venv/bin/python"

echo "== ScopeRail install =="
[ -x "$PY" ] || { echo "creating venv"; python3 -m venv "$DIR/.venv"; }
"$DIR/.venv/bin/pip" install -q --upgrade pip
"$DIR/.venv/bin/pip" install -q -r "$DIR/requirements.txt"
if [ ! -d "/Applications/Google Chrome.app" ]; then
  echo "Chrome not found; installing Playwright chromium into the ScopeRail venv"
  "$DIR/.venv/bin/python" -m playwright install chromium
fi
mkdir -p "$STATE"/{secrets,jobs,logs,backups,artifacts,browser-profile,toolpath,wshome}
chmod 711 "$STATE"; chmod 700 "$STATE/secrets"
SCOPERAIL_STATE_DIR="$STATE" "$DIR/.venv/bin/python" -c "from bridge.config import rebuild_toolpath, load_config; load_config(); print('toolpath:', rebuild_toolpath())" 2>/dev/null || true

PATH_ENV="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$PY</string><string>-m</string><string>bridge</string></array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>$PATH_ENV</string>
    <key>SCOPERAIL_STATE_DIR</key><string>$STATE</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/><key>Crashed</key><true/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$STATE/logs/scoperail.out.log</string>
  <key>StandardErrorPath</key><string>$STATE/logs/scoperail.err.log</string>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
PLIST
echo "wrote $PLIST"

mkdir -p "$HOME/bin"
ln -sf "$DIR/bin/scoperailctl" "$HOME/bin/scoperailctl"
echo "linked ~/bin/scoperailctl -> $DIR/bin/scoperailctl"
# Keep an existing legacy command working for operators upgrading from the pre-ScopeRail name.
if [ -e "$HOME/bin/bridgectl" ] || [ -d "$LEGACY_STATE" ]; then
  ln -sf "$DIR/bin/bridgectl" "$HOME/bin/bridgectl"
fi

UID_NUM="$(id -u)"
launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
launchctl bootout "gui/$UID_NUM/$LEGACY_LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$UID_NUM" "$PLIST"
launchctl kickstart -k "gui/$UID_NUM/$LABEL"
sleep 2
echo "== status =="
"$DIR/bin/scoperailctl" status || true
echo
echo "Next steps:"
echo "  1) Set the operator passphrase: scoperailctl passphrase set"
echo "  2) Register a workspace:        scoperailctl workspace add <dir> --name <n> --profiles sandboxed[,trusted-host]"
echo "  3) Local-only use is ready. For remote MCP, set an HTTPS issuer/resource first:"
echo "       scoperailctl public-url https://<your-host>/<path>"
echo "  4) If using Tailscale Funnel:   scoperailctl funnel on"
echo "  5) Connect the MCP client to:   <public_url>/mcp"
