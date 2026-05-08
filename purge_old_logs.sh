#!/bin/bash
# purge_old_logs — delete trace and access-log files older than 30 days.
#
# Background: /privacy promises 30-day log retention. Without an automated
# purge, the promise is unimplemented and silently violated as logs accumulate.
# This script runs daily from cron.
#
# What gets deleted:
#   logs/access.log.*          rotated access-log archives older than 30 days
#   traces/*.jsonl             trace files (one per UTC day) older than 30 days
#
# What does NOT get deleted:
#   logs/access.log            current access log (rotated by the server)
#   logs/server.log            stdout/stderr (kept for crash forensics)
#   logs/tunnel.log            cloudflared output (kept for crash forensics)
#   state/                     signing secret, salt, pidfiles
#   private/                   internal docs (separate from runtime)
#
# Usage:
#   ./purge_old_logs.sh           # run once (cron)
#   ./purge_old_logs.sh --dry-run # show what would be deleted without deleting
#
# Cron entry (install separately, see monitor/CRON.md):
#   15 3 * * * /home/Armada/toA/probe/02_verify_action/purge_old_logs.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
TRACES_DIR="$SCRIPT_DIR/traces"
STATE_DIR="$SCRIPT_DIR/state"
RUN_LOG="$STATE_DIR/purge_old_logs.log"
mkdir -p "$STATE_DIR"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

# Patterns to purge after 30 days.
# Use -mtime +30 (older than 30 days) on regular files only.
PURGE_PATTERNS=(
    "$LOG_DIR/access.log.*"
    "$TRACES_DIR/*.jsonl"
)

deleted=0
failed=0

for pattern in "${PURGE_PATTERNS[@]}"; do
    parent="$(dirname "$pattern")"
    name="$(basename "$pattern")"
    [ -d "$parent" ] || continue

    while IFS= read -r -d '' f; do
        if [ "$DRY_RUN" = "1" ]; then
            echo "[dry-run] would delete: $f"
        else
            if rm -f "$f"; then
                deleted=$((deleted + 1))
            else
                failed=$((failed + 1))
                echo "[$(ts)] FAILED to delete $f" >> "$RUN_LOG"
            fi
        fi
    done < <(find "$parent" -maxdepth 1 -type f -name "$name" -mtime +30 -print0 2>/dev/null)
done

if [ "$DRY_RUN" = "0" ]; then
    echo "[$(ts)] purge complete; deleted=$deleted failed=$failed" >> "$RUN_LOG"
fi

exit 0
