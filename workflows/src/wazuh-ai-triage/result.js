// Final record of this run: the triage result plus whether the notification was delivered.
// This is what you see in n8n's execution history (an audit trail).
//
// If Telegram is enabled and the message could not be sent (after the node's own
// retries), this node fails on purpose. The execution is then marked as failed,
// the error workflow (workflows/error-alerts.json) runs, and you can retry the
// execution from n8n's Executions list. A failure is never reported as success.

const triaged = $('Parse & Score').item.json;
const reply = $input.item.json || {};
const telegramEnabled = String($env.TELEGRAM_ENABLED ?? 'true').trim().toLowerCase() !== 'false';

let notification;
if (!telegramEnabled) {
  notification = 'disabled (TELEGRAM_ENABLED=false)';
} else if (reply.ok === true) {
  notification = 'sent';
} else {
  const error = reply.error ? String(reply.error.message || reply.error).slice(0, 200) : '';
  throw new Error(
    `Telegram notification for alert ${triaged.alert_id || '?'} (rule ${triaged.rule.id}) was not sent: ` +
    `${error || 'no ok:true in the reply'}. Check TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID, then retry this execution.`,
  );
}

return { json: { ...triaged, notification } };
