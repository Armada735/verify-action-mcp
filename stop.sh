#!/bin/bash
# Stop verify_action cleanly.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$SCRIPT_DIR/state"

stopped=0
for label in server tunnel; do
    pidfile="$STATE_DIR/${label}.pid"
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile" 2>/dev/null || true)
        if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
            echo "Stopped $label (PID $pid)"
            stopped=$((stopped + 1))
        fi
        rm -f "$pidfile"
    fi
done

pkill -f "python3 $SCRIPT_DIR/server.py" 2>/dev/null && stopped=$((stopped + 1)) || true
pkill -f "cloudflared tunnel.*run verify-action" 2>/dev/null && stopped=$((stopped + 1)) || true

if [ "$stopped" -eq 0 ]; then
    echo "Nothing to stop."
fi

rm -f "$STATE_DIR/current_url.txt"
echo "Done."
