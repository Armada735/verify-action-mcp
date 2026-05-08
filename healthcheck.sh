#!/bin/bash
# cron-callable health probe. Quiet on success; alerts Discord on failure.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$SCRIPT_DIR/state"
URL_FILE="$STATE_DIR/current_url.txt"
LOG_DIR="$SCRIPT_DIR/logs"
HC_LOG="$LOG_DIR/healthcheck.log"

mkdir -p "$LOG_DIR"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

if [ ! -s "$URL_FILE" ]; then
    echo "[$(ts)] FAILED: state/current_url.txt missing or empty" >> "$HC_LOG"
    # Silence in this case is worse than noise — service likely needs manual restart.
    ENV_FILE="$SCRIPT_DIR/../../research/.env"
    if [ -f "$ENV_FILE" ]; then
        set -a
        # shellcheck disable=SC1090
        source "$ENV_FILE"
        set +a
    fi
    if [ -n "${DISCORD_WEBHOOK:-}" ] && command -v jq >/dev/null 2>&1; then
        payload=$(jq -n --arg c "[verify_action] HEALTHCHECK: state/current_url.txt missing — start.sh has not been run, or stop.sh wiped it. Service is unreachable." '{content: $c}')
        curl -sS --max-time 10 -X POST -H "Content-Type: application/json" \
            -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
    fi
    exit 1
fi
URL=$(cat "$URL_FILE")

if curl -sS --doh-url https://cloudflare-dns.com/dns-query --max-time 10 "$URL/healthcheck" 2>/dev/null | grep -q "^ok$"; then
    echo "[$(ts)] OK $URL" >> "$HC_LOG"
    exit 0
fi

echo "[$(ts)] FAILED $URL" >> "$HC_LOG"

# Optional Discord notify.
ENV_FILE="$SCRIPT_DIR/../../research/.env"
if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

if [ -n "${DISCORD_WEBHOOK:-}" ] && command -v jq >/dev/null 2>&1; then
    payload=$(jq -n --arg c "[verify_action] Health check FAILED at $URL" '{content: $c}')
    curl -sS --max-time 10 -X POST -H "Content-Type: application/json" \
        -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
fi

exit 1
