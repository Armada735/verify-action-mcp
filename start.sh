#!/bin/bash
# Start verify_action: server.py + cloudflared Quick Tunnel.
# Idempotent. Detached from session (setsid + nohup) so it survives logout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
STATE_DIR="$SCRIPT_DIR/state"
SERVER_PID="$STATE_DIR/server.pid"
TUNNEL_PID="$STATE_DIR/tunnel.pid"
URL_FILE="$STATE_DIR/current_url.txt"
CLOUDFLARED="$HOME/.local/bin/cloudflared"
PORT=8092

mkdir -p "$LOG_DIR" "$STATE_DIR" "$SCRIPT_DIR/traces"
# Defense-in-depth: directories holding logs / state / traces must be 700.
chmod 700 "$LOG_DIR" "$STATE_DIR" "$SCRIPT_DIR/traces" 2>/dev/null || true

# Refuse if already running. Two checks:
#  1. PID file alive — the normal path.
#  2. Something else is already bound to PORT — a previous run started
#     bare (`python3 server.py`) without start.sh would leave no PID file
#     behind, but the port would be held. Fail fast with a clear message
#     instead of letting bind() race.
for pidfile in "$SERVER_PID" "$TUNNEL_PID"; do
    if [ -f "$pidfile" ]; then
        old=$(cat "$pidfile" 2>/dev/null || echo "")
        if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
            echo "Already running (PID $old in $(basename "$pidfile")). Stop first."
            exit 1
        fi
        rm -f "$pidfile"
    fi
done

# Port-held check (covers the bare-launch case where someone ran
# `python3 server.py` directly without start.sh).
if ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q .; then
    held_pid=$(ss -tlnHp "sport = :$PORT" 2>/dev/null \
        | grep -oE "pid=[0-9]+" | head -1 | cut -d= -f2 || true)
    echo "Port $PORT is already held"
    if [ -n "$held_pid" ]; then
        echo "  by PID $held_pid ($(ps -o comm= -p "$held_pid" 2>/dev/null || echo unknown))"
    fi
    echo "Stop the existing server first (e.g. ./stop.sh, or kill $held_pid)."
    exit 1
fi

# Start the HTTP server (binds 127.0.0.1:8092).
cd "$SCRIPT_DIR"
setsid nohup python3 "$SCRIPT_DIR/server.py" \
    >"$LOG_DIR/server.log" 2>&1 < /dev/null &
SRV_LAUNCHER_PID=$!
sleep 1

# Find the actual python3 PID via the listening socket on PORT.
SRV_REAL_PID=""
for tries in 1 2 3 4 5; do
    SRV_REAL_PID=$(ss -tlnp 2>/dev/null \
        | awk -v port=":$PORT" '$0 ~ port' \
        | grep -oE "pid=[0-9]+" | head -1 | cut -d= -f2)
    if [ -n "$SRV_REAL_PID" ]; then
        break
    fi
    sleep 1
done
if [ -z "$SRV_REAL_PID" ]; then
    SRV_REAL_PID="$SRV_LAUNCHER_PID"
fi
echo "$SRV_REAL_PID" > "$SERVER_PID"

if ! kill -0 "$SRV_REAL_PID" 2>/dev/null; then
    echo "Server failed to start. See $LOG_DIR/server.log"
    tail -20 "$LOG_DIR/server.log" || true
    rm -f "$SERVER_PID"
    exit 1
fi

# Wait for the local socket to accept.
for i in $(seq 1 10); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/healthcheck" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Start cloudflared Quick Tunnel.
: > "$LOG_DIR/tunnel.log"
setsid nohup "$CLOUDFLARED" tunnel --url "http://localhost:$PORT" \
    --no-autoupdate \
    >"$LOG_DIR/tunnel.log" 2>&1 < /dev/null &
TUN_LAUNCHER_PID=$!
sleep 1

TUN_REAL_PID=$(pgrep -f "cloudflared tunnel --url http://localhost:$PORT" 2>/dev/null \
    | grep -v "^$$\$" | head -1 || true)
if [ -z "$TUN_REAL_PID" ]; then
    TUN_REAL_PID="$TUN_LAUNCHER_PID"
fi
echo "$TUN_REAL_PID" > "$TUNNEL_PID"

# Wait for the trycloudflare URL to appear in the log.
echo "Waiting for tunnel URL..."
URL=""
for i in $(seq 1 60); do
    URL=$(grep -oE "https://[a-z0-9-]+\.trycloudflare\.com" "$LOG_DIR/tunnel.log" 2>/dev/null | head -1 || true)
    if [ -n "$URL" ]; then
        echo "$URL" > "$URL_FILE"
        echo "Tunnel URL: $URL"
        break
    fi
    sleep 1
done

if [ -z "$URL" ]; then
    echo "Failed to obtain tunnel URL after 60s. Tunnel log:"
    tail -30 "$LOG_DIR/tunnel.log"
    exit 1
fi

# Self-test via the public URL.
echo "Self-test (via Cloudflare DoH to bypass local DNS)..."
sleep 2
if curl -sS --doh-url https://cloudflare-dns.com/dns-query --max-time 15 "$URL/healthcheck" 2>/dev/null | grep -q "^ok$"; then
    echo "Self-test passed: $URL/healthcheck = ok"
else
    echo "WARNING: self-test via tunnel did not return ok within 15s"
    echo "(DNS propagation may still be in progress; check again in ~1 minute)"
fi

cat <<INFO

==========================================
verify_action running.
  Internal:  http://127.0.0.1:$PORT
  Public:    $URL
  Endpoints: /about /healthcheck /spec /stats
             POST /verify  (REST)
             POST /mcp     (JSON-RPC: initialize, tools/list, tools/call)
  Stop:      $SCRIPT_DIR/stop.sh
==========================================
INFO
