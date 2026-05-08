#!/bin/bash
# Watchdog: re-launch server.py and cloudflared if either is dead.
# Designed to run from cron every 2 min. Quiet on success; logs failures.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
STATE_DIR="$SCRIPT_DIR/state"
WD_LOG="$LOG_DIR/watchdog.log"
WD_LOCK="$STATE_DIR/watchdog.lock"
SERVER_PID="$STATE_DIR/server.pid"
TUNNEL_PID="$STATE_DIR/tunnel.pid"
URL_FILE="$STATE_DIR/current_url.txt"
PORT=8092
SERVICE_LABEL="02 verify_action"

mkdir -p "$LOG_DIR" "$STATE_DIR"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# === Flock: prevent two watchdog instances from racing on stop+start. ===
# If a previous watchdog is still running, just exit (the next tick will
# observe the result of the in-progress recovery).
exec 9>"$WD_LOCK"
if ! flock -n 9; then
    echo "[$(ts)] watchdog: another instance is running; exiting" >> "$WD_LOG"
    exit 0
fi

server_alive() {
    [ -f "$SERVER_PID" ] || return 1
    pid=$(cat "$SERVER_PID" 2>/dev/null) || return 1
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 0
    return 1
}

tunnel_alive() {
    [ -f "$TUNNEL_PID" ] || return 1
    pid=$(cat "$TUNNEL_PID" 2>/dev/null) || return 1
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 0
    return 1
}

# Both alive: nothing to do.
if server_alive && tunnel_alive; then
    exit 0
fi

# Capture pre-restart URL so we can detect rotation and notify on success.
OLD_URL=""
[ -s "$URL_FILE" ] && OLD_URL=$(cat "$URL_FILE")

# Something is dead — record and restart.
echo "[$(ts)] watchdog firing: server_alive=$(server_alive && echo yes || echo no), tunnel_alive=$(tunnel_alive && echo yes || echo no), old_url=${OLD_URL:-<none>}" >> "$WD_LOG"

# Source env (Discord webhook) once; reused on both success-rotation and
# hard-failure paths.
ENV_FILE="$SCRIPT_DIR/../../research/.env"
if [ -f "$ENV_FILE" ]; then
    set -a; source "$ENV_FILE"; set +a
fi

discord_notify() {
    local msg="$1"
    if [ -n "${DISCORD_WEBHOOK:-}" ] && command -v jq >/dev/null 2>&1; then
        local payload
        payload=$(jq -n --arg c "$msg" '{content: $c}')
        curl -sS --max-time 10 -X POST -H "Content-Type: application/json" \
            -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
    fi
}

# Clean up stale state and restart.
# stop.sh sends SIGTERM but doesn't wait for processes to fully exit; the
# listening socket on port 8092 can remain in transient state for a moment
# even after the server process exits. Sleep long enough that the kernel
# has released the bind. Failure-test 2026-05-08 showed 2s was occasionally
# too short (first watchdog tick fell through, second succeeded); 5s gives
# margin and brings expected recovery time from ~4 min to ~2 min.
"$SCRIPT_DIR/stop.sh" >> "$WD_LOG" 2>&1
sleep 5
"$SCRIPT_DIR/start.sh" >> "$WD_LOG" 2>&1

if server_alive && tunnel_alive; then
    echo "[$(ts)] watchdog: recovery OK" >> "$WD_LOG"
    NEW_URL=""
    [ -s "$URL_FILE" ] && NEW_URL=$(cat "$URL_FILE")
    # If the public URL changed, notify Discord so any embedded clients can
    # be updated. Cloudflare Quick Tunnel issues a new hostname on every
    # restart; the operator must re-publish.
    if [ -n "$NEW_URL" ] && [ "$NEW_URL" != "$OLD_URL" ]; then
        discord_notify "[$SERVICE_LABEL] watchdog: tunnel URL rotated: ${OLD_URL:-<none>} -> $NEW_URL  (any embedded badges/MCP-client configs need to be updated)"
    fi
    exit 0
else
    echo "[$(ts)] watchdog: recovery FAILED — manual intervention needed" >> "$WD_LOG"
    discord_notify "[$SERVICE_LABEL] WATCHDOG: server/tunnel restart FAILED on $(hostname)"
    exit 1
fi
