#!/bin/bash
# backup_state — encrypt state/ files and push to private off-host backup repo.
#
# Background: state/ holds the HMAC signing secret and IP-hash salt. A disk
# crash on this host would mean past receipts cannot be re-verified (because
# the secret is gone) and the IP-hash chain restarts (so old hashes can't be
# correlated for abuse forensics). Off-host backup lets us recover.
#
# Encryption: openssl AES-256-CBC with PBKDF2 (100k iterations). Passphrase
# read from $HOME/.aar-backup-passphrase (chmod 600). The passphrase is the
# only thing keeping a leaked backup safe — keep it in a password manager.
#
# Destination: private GitHub repo Armada735/aar-state-backup, cloned at
# $HOME/.aar-state-backup.
#
# Schedule: daily via cron (see monitor/CRON.md). Idempotent — re-running on
# the same day overwrites that day's backup.
#
# Restore: see restore_state.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$SCRIPT_DIR/state"
BACKUP_REPO="$HOME/.aar-state-backup"
PASSPHRASE_FILE="$HOME/.aar-backup-passphrase"
LOG="$SCRIPT_DIR/state/backup.log"
DATE=$(date -u +"%Y-%m-%d")
mkdir -p "$SCRIPT_DIR/state"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

err() {
    echo "[$(ts)] ERROR: $*" >> "$LOG" 2>/dev/null || true
    echo "ERROR: $*" >&2
    exit 1
}

# Pre-flight checks.
[ -d "$STATE_DIR" ] || err "state/ not found at $STATE_DIR"
[ -f "$STATE_DIR/aar_signing_secret" ] || err "state/aar_signing_secret missing — nothing to back up"
[ -d "$BACKUP_REPO/.git" ] || err "$BACKUP_REPO is not a git working tree (clone Armada735/aar-state-backup first)"
[ -f "$PASSPHRASE_FILE" ] || err "passphrase file missing at $PASSPHRASE_FILE (chmod 600 expected)"
# Refuse to run if passphrase file is world-readable (defense in depth).
if [ "$(stat -c %a "$PASSPHRASE_FILE" 2>/dev/null)" != "600" ]; then
    err "$PASSPHRASE_FILE must be chmod 600 (currently $(stat -c %a "$PASSPHRASE_FILE"))"
fi

# Encrypt: tar (state/aar_signing_secret + state/ip_hash_salt) → openssl.
# The lock file watchdog.lock and runtime logs (purge_old_logs.log) are
# excluded — backups should hold only the persistent secrets.
OUT="$BACKUP_REPO/state_$DATE.tar.gz.enc"
tar -cz -C "$SCRIPT_DIR" \
    state/aar_signing_secret \
    state/ip_hash_salt \
    2>/dev/null | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -pass "file:$PASSPHRASE_FILE" \
        -out "$OUT"

# Sanity: encrypted output should not be empty and should round-trip decode.
[ -s "$OUT" ] || err "encrypted output empty"
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
    -pass "file:$PASSPHRASE_FILE" \
    -in "$OUT" | tar -tz >/dev/null 2>&1 \
    || err "encrypted output failed round-trip decode (passphrase mismatch?)"

# Commit + push.
cd "$BACKUP_REPO"
git add "state_$DATE.tar.gz.enc"
if git diff --cached --quiet 2>/dev/null; then
    echo "[$(ts)] no change in encrypted blob (re-running same day)" >> "$LOG"
else
    git commit -m "backup $DATE" --quiet
    git push origin main --quiet 2>>"$LOG" || err "push failed (see log)"
    echo "[$(ts)] backed up $OUT to remote" >> "$LOG"
fi

# Keep at most 60 daily backups locally; older are dropped (history stays in
# git, so even after rm we can checkout an older commit to recover).
old=$(ls -1t "$BACKUP_REPO"/state_*.tar.gz.enc 2>/dev/null | tail -n +61 || true)
if [ -n "$old" ]; then
    cd "$BACKUP_REPO"
    echo "$old" | xargs -r git rm --quiet
    if ! git diff --cached --quiet 2>/dev/null; then
        git commit -m "prune backups older than 60 days" --quiet
        git push origin main --quiet || true
    fi
fi

exit 0
