// Check the model's answer against the JSON schema, keep the different opinions
// apart (Wazuh severity, model assessment, threat intel), set the priority by a
// fixed policy, decide on the (dry-run) block recommendation and build the message.
//
// Policy, in plain words:
// - The model's answer is used only if it passes the schema exactly. Anything else
//   (missing fields, wrong types, "false" as text, extra fields) is a failed analysis:
//   the alert falls back to its Wazuh severity and never gets a block recommendation.
// - Priority = the higher of the Wazuh severity and the model severity. The model can
//   raise the priority but never lower it below what the Wazuh rule says.
// - If the model calls a high/critical Wazuh alert low or a false positive, the alert
//   is marked "needs human review" instead of being quietly downgraded.
// - risk_score is a heuristic (0-100) used only to gate the dry-run block
//   recommendation. It is not a probability, and AbuseIPDB 0 does not mean "innocent".

const request = $('Build LLM Request').item.json;
const alert = { ...request };
delete alert.llm_request;
const response = $input.item.json || {};
const SCHEMA = request.llm_request.response_format.json_schema.schema;
const MAX_REPLY_CHARS = 8000;

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const SEVERITY_SCORE = { low: 25, medium: 50, high: 75, critical: 95 };
const SEVERITY_ICON = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' };

const configErrors = [];
const rawThreshold = String($env.BLOCK_THRESHOLD ?? '80').trim();
let BLOCK_THRESHOLD = null;
if (/^\d{1,3}$/.test(rawThreshold) && Number(rawThreshold) >= 1 && Number(rawThreshold) <= 100) {
  BLOCK_THRESHOLD = Number(rawThreshold);
} else {
  configErrors.push(`BLOCK_THRESHOLD must be a whole number from 1 to 100 (got "${rawThreshold.slice(0, 20)}")`);
}
const REDACT = String($env.NOTIFY_REDACT || '').trim().toLowerCase() === 'true';

// Small JSON Schema checker for the keywords SCHEMA uses. No type coercion:
// "false" is a string, not a boolean, and 90.5 is not an integer.
function validate(value, schema, path = '$') {
  const errors = [];
  const type = schema.type;
  const typeOk = {
    object: value !== null && typeof value === 'object' && !Array.isArray(value),
    array: Array.isArray(value),
    string: typeof value === 'string',
    integer: Number.isInteger(value),
    number: typeof value === 'number' && Number.isFinite(value),
    boolean: typeof value === 'boolean',
  }[type];
  if (!typeOk) return [`${path}: expected ${type}`];
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${path}: not one of ${schema.enum.join(', ')}`);
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: below ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path}: above ${schema.maximum}`);
  }
  if (type === 'string') {
    if (schema.minLength !== undefined && value.trim().length < schema.minLength) errors.push(`${path}: empty`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) errors.push(`${path}: longer than ${schema.maxLength}`);
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) errors.push(`${path}: bad format`);
  }
  if (type === 'array') {
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path}: more than ${schema.maxItems} items`);
    value.forEach((v, i) => errors.push(...validate(v, schema.items, `${path}[${i}]`)));
  }
  if (type === 'object') {
    for (const key of schema.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) errors.push(`${path}.${key}: missing`);
    }
    for (const [key, v] of Object.entries(value)) {
      if (schema.properties && schema.properties[key]) errors.push(...validate(v, schema.properties[key], `${path}.${key}`));
      else if (schema.additionalProperties === false) errors.push(`${path}.${key}: not allowed`);
    }
  }
  return errors;
}

function severityFromLevel(level) {
  if (level >= 12) return 'critical';
  if (level >= 10) return 'high';
  if (level >= 7) return 'medium';
  return 'low';
}

function maxSeverity(a, b) {
  return SEVERITIES.indexOf(a) >= SEVERITIES.indexOf(b) ? a : b;
}

function mask(text) {
  const s = String(text || '');
  return s.length <= 1 ? '*' : `${s[0]}***`;
}

let ai = null;
let aiError = '';
try {
  if (response.error) throw new Error(`model call failed: ${String(response.error.message || response.error)}`);
  const choice = (response.choices && response.choices[0]) || {};
  if (choice.finish_reason === 'length') throw new Error('model reply was cut off (raise LLM_MAX_TOKENS)');
  const content = choice.message && choice.message.content;
  if (typeof content !== 'string') throw new Error('model reply had no text content');
  if (content.length > MAX_REPLY_CHARS) throw new Error(`model reply longer than ${MAX_REPLY_CHARS} characters`);
  // Allowed wrappers: a <think>...</think> block and a ```json code fence. Nothing else.
  const text = content.replace(/<think>[\s\S]*?<\/think>/g, '').trim()
    .replace(/^```(?:json)?\s*([\s\S]*?)\s*```$/, '$1');
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error('model reply is not valid JSON');
  }
  const errors = validate(parsed, SCHEMA);
  if (errors.length) throw new Error(`model reply failed the schema: ${errors.slice(0, 5).join('; ')}`);
  ai = parsed;
} catch (e) {
  aiError = String(e.message || e).slice(0, 300);
}

const sourceSeverity = severityFromLevel(alert.rule.level);
const triage = {
  ai_ok: ai !== null,
  ai_error: aiError,
  verdict: ai ? ai.verdict : 'needs_investigation',
  model_severity: ai ? ai.severity : null,
  confidence: ai ? ai.confidence : null,
  summary: ai ? ai.summary : `AI analysis unavailable (${aiError}). Wazuh rule: ${alert.rule.description}`,
  reasoning: ai ? ai.reasoning : '',
  mitre_technique_id: ai ? ai.mitre_technique_id : (alert.rule.mitre.ids[0] || ''),
  mitre_technique_name: ai ? ai.mitre_technique_name : (alert.rule.mitre.techniques[0] || ''),
  recommended_actions: ai ? ai.recommended_actions : [],
  model_wants_block: ai ? ai.block_source_ip === true : false,
  model: String(response.model || $env.LLM_MODEL || ''),
};

const priority = triage.model_severity ? maxSeverity(sourceSeverity, triage.model_severity) : sourceSeverity;
const reviewReasons = [];
if (!triage.ai_ok) reviewReasons.push('AI analysis failed');
if (triage.ai_ok && SEVERITIES.indexOf(sourceSeverity) >= 2
  && (triage.verdict === 'false_positive' || SEVERITIES.indexOf(triage.model_severity) < SEVERITIES.indexOf(sourceSeverity) - 1)) {
  reviewReasons.push(`model rates a ${sourceSeverity} Wazuh alert as ${triage.verdict === 'false_positive' ? 'a false positive' : triage.model_severity}`);
}

// Heuristic risk score for the block gate: 70% model severity (reduced for false
// positives) + 30% AbuseIPDB, or 100% model severity without a lookup.
const abuse = alert.threat_intel.abuseipdb || {};
const abuseScore = typeof abuse.score === 'number' && Number.isFinite(abuse.score) ? abuse.score : null;
let riskScore = null;
if (triage.ai_ok) {
  const aiScore = SEVERITY_SCORE[triage.model_severity] * (triage.verdict === 'false_positive' ? 0.3 : 1);
  riskScore = Math.round(abuseScore === null ? aiScore : 0.7 * aiScore + 0.3 * abuseScore);
}

// Block decision. This version never blocks: it only reports what it would do (dry-run).
let action = 'none';
let actionReason = '';
if (!alert.srcip) actionReason = 'no source IP';
else if (!alert.srcip_is_public) actionReason = 'source IP is not public';
else if (alert.srcip_whitelisted) actionReason = 'source IP is whitelisted';
else if (!triage.ai_ok) actionReason = 'no valid AI analysis';
else if (BLOCK_THRESHOLD === null) actionReason = 'BLOCK_THRESHOLD is invalid, block recommendations are off';
else if (!triage.model_wants_block) actionReason = 'model did not recommend blocking';
else if (triage.verdict !== 'true_positive') actionReason = `verdict is ${triage.verdict}`;
else if (riskScore < BLOCK_THRESHOLD) actionReason = `risk ${riskScore} is below threshold ${BLOCK_THRESHOLD}`;
else {
  action = 'would_block';
  actionReason = `risk ${riskScore} >= ${BLOCK_THRESHOLD} (dry-run, nothing was blocked)`;
}

// Notification text (plain text, Telegram limit is 4096 characters).
const agentLabel = REDACT ? `agent ${alert.agent.id || '-'}` : `${alert.agent.name || '-'}${alert.agent.id ? ` (${alert.agent.id})` : ''}`;
const lines = [
  `${SEVERITY_ICON[priority]} Wazuh AI triage: ${priority.toUpperCase()}${reviewReasons.length ? ' - NEEDS HUMAN REVIEW' : ''}`,
  '',
  `Rule ${alert.rule.id} (level ${alert.rule.level}, ${sourceSeverity}): ${alert.rule.description}`,
  `Agent: ${agentLabel}`,
];
if (alert.srcip) {
  let ipLine = `Source IP: ${alert.srcip}${alert.srcip_is_public ? '' : ' (not public)'}`;
  if (abuseScore !== null) {
    ipLine += ` | AbuseIPDB ${abuseScore}% (${abuse.total_reports ?? 0} reports${abuse.country ? `, ${abuse.country}` : ''})`;
  }
  lines.push(ipLine);
}
if (alert.srcuser) lines.push(`User: ${REDACT ? mask(alert.srcuser) : alert.srcuser}`);
if (alert.dstuser) lines.push(`Target user: ${REDACT ? mask(alert.dstuser) : alert.dstuser}`);
if (alert.syscheck) lines.push(`File: ${alert.syscheck.path} (${alert.syscheck.event || 'changed'})`);
if (triage.ai_ok) {
  lines.push(`AI: ${triage.verdict}, ${triage.model_severity} (model confidence ${triage.confidence}, uncalibrated)`);
  if (riskScore !== null) lines.push(`Risk score: ${riskScore}/100 (heuristic)`);
} else {
  lines.push('AI: analysis failed, showing the Wazuh severity');
}
if (triage.mitre_technique_id) lines.push(`MITRE: ${triage.mitre_technique_id} ${triage.mitre_technique_name}`.trim());
for (const reason of reviewReasons) lines.push(`Review: ${reason}`);
lines.push('', triage.summary);
if (triage.recommended_actions.length) {
  lines.push('', 'Recommended:');
  for (const step of triage.recommended_actions) lines.push(`- ${step}`);
}
lines.push('');
lines.push(action === 'would_block' ? `Action: would block ${alert.srcip} (dry-run)` : `Action: none (${actionReason})`);
if (alert.duplicates_suppressed > 0) lines.push(`Similar alerts suppressed before this one: ${alert.duplicates_suppressed}`);
for (const warning of [...(alert.config_warnings || []), ...configErrors]) lines.push(`Config: ${warning}`);
lines.push(`Time: ${alert.timestamp || alert.received_at}`);

return {
  json: {
    ...alert,
    triage,
    source_severity: sourceSeverity,
    priority,
    needs_human_review: reviewReasons.length > 0,
    review_reasons: reviewReasons,
    risk_score: riskScore,
    action,
    action_reason: actionReason,
    config_errors: configErrors,
    message: lines.join('\n').slice(0, 4000),
  },
};
