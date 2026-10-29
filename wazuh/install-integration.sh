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
#   1. Copies custom-n8n, custom-n8n.py and custom-n8n.conf to /var/ossec/integrations
#   2. Backs up ossec.conf and adds (or replaces) the integration block
#   3. Restarts wazuh-manager, and restores the backup if it fails to start
# If WEBHOOK_SECRET is not set, a random secret is generated and printed.
# DEDUP_WINDOW_SECONDS (default 600) sets the Wazuh-side dedup window.
set -euo pipefail

WAZUH_DIR="${WAZUH_DIR:-/var/ossec}"
CONF="${WAZUH_DIR}/etc/ossec.conf"
HERE="$(cd "$(dirname "$0")" && pwd -P)"
HOOK_URL="${1:-}"
LEVEL="${2:-7}"
MARK_START="<!-- wazuh-ai-triage:start -->"
MARK_END="<!-- wazuh-ai-triage:end -->"

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run with sudo"
[ -f "$CONF" ] || die "$CONF not found. Is the Wazuh manager installed here?"
[[ "$HOOK_URL" =~ ^https?://[A-Za-z0-9.:/_-]+$ ]] || die "usage: $0 <n8n_webhook_url> [min_level]"
[[ "$LEVEL" =~ ^([0-9]|1[0-5])$ ]] || die "min_level must be 0-15"
WINDOW="${DEDUP_WINDOW_SECONDS:-600}"
[[ "$WINDOW" =~ ^[0-9]{1,6}$ ]] || die "DEDUP_WINDOW_SECONDS must be a number of seconds"

SECRET="${WEBHOOK_SECRET:-}"
GENERATED=0
if [ -z "$SECRET" ]; then
  SECRET="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
  GENERATED=1
fi
[[ "$SECRET" =~ ^[A-Za-z0-9._-]{16,128}$ ]] || die "WEBHOOK_SECRET must be 16-128 chars of letters, digits, . _ -"

GROUP="wazuh"
getent group wazuh >/dev/null || GROUP="ossec"

echo "==> Copying integration scripts"
install -m 750 -o root -g "$GROUP" "$HERE/integrations/custom-n8n" "$WAZUH_DIR/integrations/custom-n8n"
install -m 750 -o root -g "$GROUP" "$HERE/integrations/custom-n8n.py" "$WAZUH_DIR/integrations/custom-n8n.py"
printf 'DEDUP_WINDOW_SECONDS=%s\n' "$WINDOW" > "$WAZUH_DIR/integrations/custom-n8n.conf"
chown root:"$GROUP" "$WAZUH_DIR/integrations/custom-n8n.conf"
chmod 640 "$WAZUH_DIR/integrations/custom-n8n.conf"

BACKUP="${CONF}.bak-$(date +%Y%m%d-%H%M%S)-$$"
echo "==> Backing up ossec.conf to $BACKUP"
cp -p "$CONF" "$BACKUP"

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
if ! systemctl restart wazuh-manager || ! systemctl is-active --quiet wazuh-manager; then
  echo "wazuh-manager did not start. Restoring the backup." >&2
  cp -p "$BACKUP" "$CONF"
  systemctl restart wazuh-manager || true
  die "install failed; ossec.conf was restored. Check: sudo journalctl -u wazuh-manager -n 50"
fi

echo
echo "Done. Alerts of level >= $LEVEL now go to: $HOOK_URL"
if [ "$GENERATED" -eq 1 ]; then
  echo
  echo "A new webhook secret was generated. Put this line in the .env file next to"
  echo "docker-compose.yml on the n8n machine, then run: docker compose up -d"
  echo
  echo "    WEBHOOK_SECRET=${SECRET}"
fi
echo
echo "Integration log: $WAZUH_DIR/logs/integrations.log"
