#!/usr/bin/env bash
# Install Cait Local Bridge as a launchd user service that runs independently of any Claude Code / Codex session.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${CLB_STATE_DIR:-$HOME/.cait-local-bridge}"
PLIST="$HOME/Library/LaunchAgents/com.cait.local-bridge.plist"
LABEL="com.cait.local-bridge"
PY="$DIR/.venv/bin/python"

echo "== Cait Local Bridge install =="
[ -x "$PY" ] || { echo "creating venv"; python3 -m venv "$DIR/.venv"; }
"$DIR/.venv/bin/pip" install -q --upgrade pip
"$DIR/.venv/bin/pip" install -q -r "$DIR/requirements.txt"
# Playwright browser: prefer the user's Chrome channel; fall back to bundled chromium.
if [ ! -d "/Applications/Google Chrome.app" ]; then
  echo "Chrome not found; installing Playwright chromium into the bridge venv"
  "$DIR/.venv/bin/python" -m playwright install chromium
fi
mkdir -p "$STATE"/{secrets,jobs,logs,backups,artifacts,browser-profile,toolpath,wshome}
chmod 711 "$STATE"; chmod 700 "$STATE/secrets"
"$DIR/.venv/bin/python" -c "from bridge.config import rebuild_toolpath, load_config; load_config(); print('toolpath:', rebuild_toolpath())" 2>/dev/null || true

# launchd plist: fixed PATH with no Claude Code / Codex dirs; RunAtLoad + KeepAlive.
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
    <key>CLB_STATE_DIR</key><string>$STATE</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/><key>Crashed</key><true/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$STATE/logs/bridge.out.log</string>
  <key>StandardErrorPath</key><string>$STATE/logs/bridge.err.log</string>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
PLIST
echo "wrote $PLIST"

# symlink bridgectl onto PATH for the user
mkdir -p "$HOME/bin"
ln -sf "$DIR/bin/bridgectl" "$HOME/bin/bridgectl"
echo "linked ~/bin/bridgectl -> $DIR/bin/bridgectl"

UID_NUM="$(id -u)"
launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$UID_NUM" "$PLIST"
launchctl kickstart -k "gui/$UID_NUM/$LABEL"
sleep 2
echo "== status =="
"$DIR/bin/bridgectl" status || true
echo
echo "Next steps:"
echo "  1) Set the bridge passphrase:   bridgectl passphrase set"
echo "  2) Register a workspace:        bridgectl workspace add <dir> --name <n> --profiles sandboxed[,trusted-host]"
echo "  3) Local-only use is ready. For remote MCP, set an HTTPS issuer/resource first:"
echo "       bridgectl public-url https://<your-host>/<path>"
echo "  4) If using Tailscale Funnel:   bridgectl funnel on"
echo "  5) Connect the MCP client to:   <public_url>/mcp"
