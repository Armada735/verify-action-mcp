#!/bin/bash
# restore_state — decrypt the most recent (or specified) backup back into
# state/. Idempotent: writes to state/ alongside any existing files.
#
# Usage:
#   ./restore_state.sh                        # restore latest backup
#   ./restore_state.sh state_2026-05-08.tar.gz.enc   # restore specific date
#   ./restore_state.sh --list                 # list available backups
#
# This is the disaster-recovery counterpart to backup_state.sh. Running this
# overwrites state/aar_signing_secret and state/ip_hash_salt with the values
# from the backup. **Do NOT run this on a host already in production unless
# you intend to roll back the secrets** — old receipts won't verify under a
# different secret.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$SCRIPT_DIR/state"
BACKUP_REPO="$HOME/.aar-state-backup"
PASSPHRASE_FILE="$HOME/.aar-backup-passphrase"

err() { echo "ERROR: $*" >&2; exit 1; }

[ -d "$BACKUP_REPO/.git" ] || err "$BACKUP_REPO not found; clone Armada735/aar-state-backup first"
[ -f "$PASSPHRASE_FILE" ] || err "passphrase file missing at $PASSPHRASE_FILE"

if [ "${1:-}" = "--list" ]; then
    echo "Available backups:"
    ls -1t "$BACKUP_REPO"/state_*.tar.gz.enc 2>/dev/null | head -20
    exit 0
fi

# Refresh local clone to ensure we restore from latest.
cd "$BACKUP_REPO"
git pull --quiet origin main || true

if [ -n "${1:-}" ]; then
    SRC="$BACKUP_REPO/$1"
    [ -f "$SRC" ] || err "backup not found: $1"
else
    SRC=$(ls -1t "$BACKUP_REPO"/state_*.tar.gz.enc 2>/dev/null | head -1 || true)
    [ -n "$SRC" ] || err "no backups found in $BACKUP_REPO"
    echo "Using latest: $(basename "$SRC")"
fi

# Decrypt + extract directly into project root (creates state/ if missing).
mkdir -p "$STATE_DIR"
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
    -pass "file:$PASSPHRASE_FILE" \
    -in "$SRC" | tar -xz -C "$SCRIPT_DIR" \
    || err "decrypt or extract failed (wrong passphrase? corrupted backup?)"

chmod 700 "$STATE_DIR" 2>/dev/null || true
chmod 600 "$STATE_DIR"/aar_signing_secret "$STATE_DIR"/ip_hash_salt 2>/dev/null || true

echo "Restored from $(basename "$SRC")"
echo "Files now present:"
ls -la "$STATE_DIR"/aar_signing_secret "$STATE_DIR"/ip_hash_salt
