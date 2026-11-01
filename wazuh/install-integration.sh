#!/usr/bin/env bash
# Install the Wazuh -> n8n integration on the Wazuh manager.
#
# Usage:
#   sudo ./install-integration.sh <n8n_webhook_url> [min_level]
#
# Example:
#   sudo WEBHOOK_SECRET=... ./install-integration.sh http://192.168.1.20:5678/webhook/wazuh-alert 7
#
# What it does:
#   1. Backs up ossec.conf and any integration files from an earlier install
#   2. Copies custom-n8n, custom-n8n.py and custom-n8n.conf to /var/ossec/integrations
#   3. Adds (or replaces) the integration block in ossec.conf
#   4. Restarts wazuh-manager. If anything fails, everything from step 1 is restored.
#
# The webhook secret:
#   - WEBHOOK_SECRET set: that value is used.
#   - Not set, and an earlier install exists: the existing secret is kept, so n8n
#     keeps accepting alerts.
#   - Not set and no earlier install, or ROTATE_SECRET=1: a new random secret is
#     generated and printed. Put it in n8n's .env too, or alerts will get 401.
# DEDUP_WINDOW_SECONDS (default 600) sets the Wazuh-side dedup window.
#
# For tests: WAZUH_DIR, WAZUH_GROUP and SYSTEMCTL can point somewhere else.
set -euo pipefail

WAZUH_DIR="${WAZUH_DIR:-/var/ossec}"
CONF="${WAZUH_DIR}/etc/ossec.conf"
INT_DIR="${WAZUH_DIR}/integrations"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
HERE="$(cd "$(dirname "$0")" && pwd -P)"
HOOK_URL="${1:-}"
LEVEL="${2:-7}"
MARK_START="<!-- wazuh-ai-triage:start -->"
MARK_END="<!-- wazuh-ai-triage:end -->"
FILES=(custom-n8n custom-n8n.py custom-n8n.conf)

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run with sudo"
[ -f "$CONF" ] || die "$CONF not found. Is the Wazuh manager installed here?"
[[ "$HOOK_URL" =~ ^https?://[A-Za-z0-9.:/_-]+$ ]] || die "usage: $0 <n8n_webhook_url> [min_level]"
[[ "$LEVEL" =~ ^([0-9]|1[0-5])$ ]] || die "min_level must be 0-15"
WINDOW="${DEDUP_WINDOW_SECONDS:-600}"
[[ "$WINDOW" =~ ^[0-9]{1,6}$ ]] || die "DEDUP_WINDOW_SECONDS must be a number of seconds"

# Secret: explicit > existing (unless rotating) > new.
EXISTING="$(sed -n "\|${MARK_START}|,\|${MARK_END}|s|.*<api_key>\(.*\)</api_key>.*|\1|p" "$CONF" | head -n1)"
SECRET="${WEBHOOK_SECRET:-}"
SECRET_SOURCE="given"
if [ -z "$SECRET" ] && [ -n "$EXISTING" ] && [ "${ROTATE_SECRET:-0}" != "1" ]; then
  SECRET="$EXISTING"
  SECRET_SOURCE="kept"
fi
if [ -z "$SECRET" ]; then
  SECRET="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
  SECRET_SOURCE="generated"
fi
[[ "$SECRET" =~ ^[A-Za-z0-9._-]{16,128}$ ]] || die "WEBHOOK_SECRET must be 16-128 chars of letters, digits, . _ -"

GROUP="${WAZUH_GROUP:-}"
if [ -z "$GROUP" ]; then
  GROUP="wazuh"
  getent group wazuh >/dev/null || GROUP="ossec"
fi

STAMP="$(date +%Y%m%d-%H%M%S)-$$"
BACKUP_DIR="${WAZUH_DIR}/etc/wazuh-ai-triage-backup-${STAMP}"
echo "==> Backing up ossec.conf and earlier integration files to $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
cp -p "$CONF" "$BACKUP_DIR/ossec.conf"
for f in "${FILES[@]}"; do
  if [ -e "$INT_DIR/$f" ]; then cp -p "$INT_DIR/$f" "$BACKUP_DIR/$f"; fi
done

DONE=0
rollback() {
  [ "$DONE" -eq 1 ] && return
  echo "Install failed. Restoring the backup from $BACKUP_DIR" >&2
  cp -p "$BACKUP_DIR/ossec.conf" "$CONF"
  for f in "${FILES[@]}"; do
    if [ -e "$BACKUP_DIR/$f" ]; then cp -p "$BACKUP_DIR/$f" "$INT_DIR/$f"; else rm -f "$INT_DIR/$f"; fi
  done
  "$SYSTEMCTL" restart wazuh-manager || true
  echo "Restored. Check: sudo journalctl -u wazuh-manager -n 50" >&2
}
trap rollback EXIT

echo "==> Copying integration scripts"
install -m 750 -o root -g "$GROUP" "$HERE/integrations/custom-n8n" "$INT_DIR/custom-n8n"
install -m 750 -o root -g "$GROUP" "$HERE/integrations/custom-n8n.py" "$INT_DIR/custom-n8n.py"
printf 'DEDUP_WINDOW_SECONDS=%s\n' "$WINDOW" > "$INT_DIR/custom-n8n.conf"
chown root:"$GROUP" "$INT_DIR/custom-n8n.conf"
chmod 640 "$INT_DIR/custom-n8n.conf"

echo "==> Writing integration block (level >= $LEVEL)"
# Remove a block from an earlier run, then append a fresh one.
sed -i "\|${MARK_START}|,\|${MARK_END}|d" "$CONF"
cat >> "$CONF" <<EOF
${MARK_START}
<ossec_config>
  <integration>
    <name>custom-n8n</name>
    <hook_url>${HOOK_URL}</hook_url>
    <api_key>${SECRET}</api_key>
    <level>${LEVEL}</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
${MARK_END}
EOF

echo "==> Restarting wazuh-manager"
"$SYSTEMCTL" restart wazuh-manager
"$SYSTEMCTL" is-active --quiet wazuh-manager
DONE=1
trap - EXIT

echo
echo "Done. Alerts of level >= $LEVEL now go to: $HOOK_URL"
case "$SECRET_SOURCE" in
  kept) echo "The webhook secret from the earlier install was kept (set ROTATE_SECRET=1 to make a new one)." ;;
  generated)
    echo
    echo "A new webhook secret was generated. Put this line in the .env file next to"
    echo "docker-compose.yml on the n8n machine, then run: docker compose up -d"
    echo
    echo "    WEBHOOK_SECRET=${SECRET}"
    ;;
esac
echo
echo "Backup: $BACKUP_DIR"
echo "Integration log: $WAZUH_DIR/logs/integrations.log"
echo "Alerts that could not be sent wait in $WAZUH_DIR/logs/custom-n8n-spool/"
