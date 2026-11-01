'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { runNode } = require('./harness');

const SECRET = 'test-secret-0123456789'; // gitleaks:allow (test placeholder)

const VALID = {
  verdict: 'true_positive', severity: 'high', confidence: 90,
  summary: 'SSH brute force from one public IP.', reasoning: 'Many failed logins.',
  mitre_technique_id: 'T1110', mitre_technique_name: 'Brute Force',
  recommended_actions: ['Block the source IP'], block_source_ip: true,
};

// Run Sanitize -> (dedup skipped) -> Build LLM Request -> Parse & Score.
async function score({ reply, raw, level = 10, srcip = '8.8.8.8', abuse = { score: 100, total_reports: 5 }, env = {} } = {}) {
  const alert = {
    id: '1.1', manager: { name: 'mgr' }, agent: { id: '000', name: 'host' },
    rule: { id: '5712', level, description: 'test rule', mitre: { id: ['T1110'], technique: ['Brute Force'] } },
    data: { srcip, srcuser: 'admin' }, full_log: 'log line',
  };
  const [sanitized] = await runNode('sanitize-validate', {
    env: { WEBHOOK_SECRET: SECRET }, items: [{ headers: { 'x-wazuh-token': SECRET }, body: alert }],
  });
  const withIntel = { ...sanitized.json, duplicates_suppressed: 0, threat_intel: { abuseipdb: abuse } };
  const built = await runNode('build-llm-request', { env, item: withIntel });
  const content = raw !== undefined ? raw : JSON.stringify(reply);
  const response = typeof content === 'object' && content !== null ? content
    : { model: 'test-model', choices: [{ message: { content }, finish_reason: 'stop' }] };
  const out = await runNode('parse-score', { env, item: response, nodes: { 'Build LLM Request': built.json } });
  return out.json;
}

test('a valid answer is accepted and can lead to a dry-run block recommendation', async () => {
  const r = await score({ reply: VALID });
  assert.equal(r.triage.ai_ok, true);
  assert.equal(r.action, 'would_block');
  assert.equal(r.risk_score, 83);
  assert.equal(r.priority, 'high');
  assert.match(r.message, /dry-run/);
});

test('an empty object is a failed analysis, not a success', async () => {
  const r = await score({ reply: {} });
  assert.equal(r.triage.ai_ok, false);
  assert.match(r.triage.ai_error, /schema/);
  assert.equal(r.action, 'none');
  assert.equal(r.risk_score, null);
  assert.equal(r.needs_human_review, true);
});

test('block_source_ip "false" (a string) is rejected, not read as true', async () => {
  const r = await score({ reply: { ...VALID, block_source_ip: 'false' } });
  assert.equal(r.triage.ai_ok, false);
  assert.equal(r.triage.model_wants_block, false);
  assert.equal(r.action, 'none');
});

test('an invalid verdict with zero confidence never leads to a block', async () => {
  const r = await score({ reply: { ...VALID, verdict: 'definitely_bad', confidence: 0 } });
  assert.equal(r.triage.ai_ok, false);
  assert.equal(r.action, 'none');
});

test('needs_investigation never leads to a block, even when the model asks for one', async () => {
  const r = await score({ reply: { ...VALID, verdict: 'needs_investigation', severity: 'critical' } });
  assert.equal(r.triage.ai_ok, true);
  assert.equal(r.action, 'none');
  assert.match(r.action_reason, /verdict/);
});

test('wrong types, extra fields, ranges and lengths are rejected', async () => {
  const bad = [
    { ...VALID, confidence: '90' },
    { ...VALID, confidence: 90.5 },
    { ...VALID, confidence: 101 },
    { ...VALID, severity: 'HIGH' },
    { ...VALID, summary: '' },
    { ...VALID, summary: 'x'.repeat(401) },
    { ...VALID, recommended_actions: ['a', 'b', 'c', 'd', 'e'] },
    { ...VALID, recommended_actions: [1] },
    { ...VALID, mitre_technique_id: 'rm -rf /' },
    { ...VALID, extra: 'field' },
    (({ reasoning, ...rest }) => rest)(VALID),
  ];
  for (const reply of bad) {
    const r = await score({ reply });
    assert.equal(r.triage.ai_ok, false, JSON.stringify(reply).slice(0, 120));
    assert.equal(r.action, 'none');
  }
});

test('text around the JSON is rejected; a think block and a json code fence are allowed', async () => {
  assert.equal((await score({ raw: `Sure! ${JSON.stringify(VALID)} Hope this helps` })).triage.ai_ok, false);
  assert.equal((await score({ raw: `<think>hmm</think>\n${JSON.stringify(VALID)}` })).triage.ai_ok, true);
  assert.equal((await score({ raw: '```json\n' + JSON.stringify(VALID) + '\n```' })).triage.ai_ok, true);
});

test('a reply cut off by max tokens is a failed analysis', async () => {
  const r = await score({ raw: { choices: [{ message: { content: '{"verdict": "tr' }, finish_reason: 'length' }] } });
  assert.equal(r.triage.ai_ok, false);
  assert.match(r.triage.ai_error, /LLM_MAX_TOKENS/);
});

test('an LLM call error falls back to the Wazuh severity', async () => {
  const r = await score({ raw: { error: { message: 'connect ECONNREFUSED' } }, level: 12 });
  assert.equal(r.triage.ai_ok, false);
  assert.equal(r.priority, 'critical');
  assert.match(r.message, /analysis failed/);
});

test('an invalid BLOCK_THRESHOLD turns block recommendations off instead of always on', async () => {
  for (const value of ['invalid', '0', '101', '-5', '50.5', '']) {
    const r = await score({ reply: { ...VALID, severity: 'medium' }, abuse: {}, env: { BLOCK_THRESHOLD: value } });
    assert.equal(r.action, 'none', `BLOCK_THRESHOLD=${value}`);
    assert.ok(r.config_errors.length > 0);
    assert.match(r.message, /Config: BLOCK_THRESHOLD/);
  }
});

test('a level 15 alert rated low / false positive keeps CRITICAL priority and asks for review', async () => {
  const r = await score({ reply: { ...VALID, verdict: 'false_positive', severity: 'low', block_source_ip: false }, level: 15, abuse: { score: 0 } });
  assert.equal(r.source_severity, 'critical');
  assert.equal(r.priority, 'critical');
  assert.equal(r.needs_human_review, true);
  assert.equal(r.risk_score, 5); // the heuristic is still low, but it no longer sets the priority
  assert.match(r.message, /NEEDS HUMAN REVIEW/);
});

test('the model can raise the priority above the Wazuh severity', async () => {
  const r = await score({ reply: { ...VALID, severity: 'critical' }, level: 5 });
  assert.equal(r.source_severity, 'low');
  assert.equal(r.priority, 'critical');
});

test('not-public, whitelisted or missing IPs never get a block recommendation', async () => {
  assert.equal((await score({ reply: VALID, srcip: '203.0.113.45' })).action, 'none');
  assert.equal((await score({ reply: VALID, srcip: '' })).action, 'none');
});

test('NOTIFY_REDACT hides host and user names in the message', async () => {
  const r = await score({ reply: VALID, env: { NOTIFY_REDACT: 'true' } });
  assert.doesNotMatch(r.message, /host|admin/);
  assert.match(r.message, /agent 000/);
  assert.match(r.message, /User: a\*\*\*/);
});
