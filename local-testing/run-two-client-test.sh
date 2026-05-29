#!/usr/bin/env bash
set -Eeuo pipefail

# Axeno local two-client test harness.
# Run this from the repo root that contains ./axeno-client and ./axeno-server.
# It will:
#   1. Delete the two local test app-data folders in ~/.local/share
#   2. Recreate ./axeno-client2 from ./axeno-client
#   3. Patch client2 to use Vite port 1421 and identifier com.hbz.axeno-client2
#   4. Run npm install in both clients
#   5. Start the relay server and both Tauri dev clients in separate terminals

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_A="$ROOT_DIR/axeno-client"
CLIENT_B="$ROOT_DIR/axeno-client2"
SERVER_DIR="$ROOT_DIR/axeno-server"

APP_ID_A="com.hbz.axeno-client"
APP_ID_B="com.hbz.axeno-client2"
PORT_A="1420"
PORT_B="1421"
RELAY_PORT="8787"

log() { printf '\033[1;36m[axeno-test]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[axeno-test warning]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[axeno-test error]\033[0m %s\n' "$*" >&2; exit 1; }

require_dir() {
  [[ -d "$1" ]] || fail "Missing directory: $1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

require_dir "$CLIENT_A"
require_dir "$SERVER_DIR"
require_cmd npm
require_cmd python3
require_cmd cargo

#log "Deleting local Axeno test app data in ~/.local/share"
#rm -rf "$HOME/.local/share/$APP_ID_A" "$HOME/.local/share/$APP_ID_B"

log "Syncing axeno-client -> axeno-client2 (preserving dependencies)"
mkdir -p "$CLIENT_B"

if command -v rsync >/dev/null 2>&1; then
  # The --delete flag removes files in CLIENT_B that no longer exist in CLIENT_A.
  # The --exclude flags prevent rsync from touching the compiled output and deps,
  # so they are preserved in CLIENT_B across runs!
  rsync -a --delete \
    --exclude node_modules \
    --exclude dist \
    --exclude target \
    --exclude .git \
    "$CLIENT_A/" "$CLIENT_B/"
else
  # Fallback if no rsync (very rare on Linux/macOS): just copy over the files.
  # This won't delete removed files, but it will overwrite changed ones without 
  # destroying the target/node_modules folders.
  cp -a "$CLIENT_A/src" "$CLIENT_A/src-tauri" "$CLIENT_A/public" "$CLIENT_B/" 2>/dev/null || true
  cp -a "$CLIENT_A/"*.* "$CLIENT_B/" 2>/dev/null || true
fi

log "Patching client2 package.json and tauri.conf.json"
python3 - "$CLIENT_B" "$APP_ID_B" "$PORT_B" <<'PY'
import json
import pathlib
import sys

client = pathlib.Path(sys.argv[1])
app_id = sys.argv[2]
port = sys.argv[3]

package_path = client / "package.json"
config_path = client / "src-tauri" / "tauri.conf.json"

pkg = json.loads(package_path.read_text())
pkg.setdefault("scripts", {})["dev"] = f"vite --port {port}"
package_path.write_text(json.dumps(pkg, indent=2) + "\n")

conf = json.loads(config_path.read_text())
conf["productName"] = "Axeno 2"
conf["identifier"] = app_id
conf.setdefault("build", {})["devUrl"] = f"http://localhost:{port}"

# Make the window title obvious when both clients are open.
windows = conf.setdefault("app", {}).setdefault("windows", [])
if windows:
    windows[0]["title"] = "Axeno 2"

# Keep CSP aligned with the second Vite port.
security = conf.setdefault("app", {}).setdefault("security", {})
csp = security.get("csp")
if isinstance(csp, dict):
    connect_src = csp.get("connect-src", "")
    additions = [
        f"http://localhost:{port}",
        f"http://127.0.0.1:{port}",
    ]
    for item in additions:
        if item not in connect_src:
            connect_src = (connect_src + " " + item).strip()
    csp["connect-src"] = connect_src

config_path.write_text(json.dumps(conf, indent=2) + "\n")
PY

log "Installing npm dependencies in client A"
(cd "$CLIENT_A" && npm install)

log "Installing npm dependencies in client B"
(cd "$CLIENT_B" && npm install)

if command -v ss >/dev/null 2>&1; then
  if ss -ltn "sport = :$RELAY_PORT" | grep -q ":$RELAY_PORT"; then
    warn "Port $RELAY_PORT already appears to be in use. If the relay fails, kill the old process with: sudo fuser -k ${RELAY_PORT}/tcp"
  fi
  if ss -ltn "sport = :$PORT_A" | grep -q ":$PORT_A"; then
    warn "Port $PORT_A already appears to be in use. Client A may fail if another Vite server is running."
  fi
  if ss -ltn "sport = :$PORT_B" | grep -q ":$PORT_B"; then
    warn "Port $PORT_B already appears to be in use. Client B may fail if another Vite server is running."
  fi
fi

run_in_terminal() {
  local title="$1"
  local dir="$2"
  local cmd="$3"
  local full_cmd="cd '$dir' && $cmd; echo; echo '[axeno-test] $title exited. Press Enter to close.'; read -r _"

  if command -v gnome-terminal >/dev/null 2>&1; then
    gnome-terminal --title="$title" -- bash -lc "$full_cmd"
  elif command -v konsole >/dev/null 2>&1; then
    konsole --new-tab -p tabtitle="$title" -e bash -lc "$full_cmd"
  elif command -v alacritty >/dev/null 2>&1; then
    alacritty -T "$title" -e bash -lc "$full_cmd" &
  elif command -v xfce4-terminal >/dev/null 2>&1; then
    xfce4-terminal --title="$title" --command="bash -lc $full_cmd"
  elif command -v x-terminal-emulator >/dev/null 2>&1 && ! readlink -f $(which x-terminal-emulator) | grep -q "xterm"; then
    x-terminal-emulator -T "$title" -e bash -lc "$full_cmd" &
  elif command -v kgx >/dev/null 2>&1; then
    kgx --title "$title" -- bash -lc "$full_cmd"
  elif command -v xterm >/dev/null 2>&1; then
    xterm -T "$title" -e bash -lc "$full_cmd" &
  else
    warn "No supported terminal emulator found. Running '$title' in the background and logging to $ROOT_DIR/${title// /_}.log"
    (cd "$dir" && bash -lc "$cmd") > "$ROOT_DIR/${title// /_}.log" 2>&1 &
  fi
}

log "Starting Axeno relay server"
run_in_terminal "Axeno Server" "$SERVER_DIR" "RUST_LOG=axeno_server=debug,tower_http=info cargo run"
sleep 2

log "Starting client A on Vite port $PORT_A"
run_in_terminal "Axeno Client A" "$CLIENT_A" "WEBKIT_DISABLE_COMPOSITING_MODE=1 npm run tauri dev"
sleep 2

log "Starting client B on Vite port $PORT_B"
run_in_terminal "Axeno Client B" "$CLIENT_B" "WEBKIT_DISABLE_COMPOSITING_MODE=1 npm run tauri dev"

log "Done. Both clients should connect to ws://127.0.0.1:$RELAY_PORT/ws"
log "Client A app data: ~/.local/share/$APP_ID_A"
log "Client B app data: ~/.local/share/$APP_ID_B"
