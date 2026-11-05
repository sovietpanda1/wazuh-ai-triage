#!/usr/bin/env node
// Run the labelled samples through a REAL model, using the workflow's own code
// (Sanitize -> Build LLM Request -> model -> Parse & Score), and compare the answers
// with samples/labels.json.
//
//   node scripts/evaluate.js --base-url http://localhost:1234/v1 --model qwen/qwen3.5-9b
//
// It reports, per sample: schema validity, verdict, severity, block recommendation and
// latency, plus the model, prompt version and settings used. Six samples are a smoke
// test of prompt changes and models, not an accuracy measure. Never run it against the
// mock server to claim accuracy: the mock only matches keywords.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { runNode, loadNode } = require('../tests/js/harness');

const ROOT = path.join(__dirname, '..');
const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const BASE_URL = opt('base-url', process.env.LLM_BASE_URL || 'http://localhost:1234/v1').replace(/\/+$/, '');
const MODEL = opt('model', process.env.LLM_MODEL || 'local-model');
const API_KEY = opt('api-key', process.env.LLM_API_KEY || 'local');
const SECRET = 'evaluation-only-secret'; // gitleaks:allow (local placeholder, never sent anywhere)
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

async function main() {
  const labels = JSON.parse(fs.readFileSync(path.join(ROOT, 'samples', 'labels.json'), 'utf8'));
  const env = { WEBHOOK_SECRET: SECRET, LLM_MODEL: MODEL, BLOCK_THRESHOLD: process.env.BLOCK_THRESHOLD || '80' };
  const promptSource = fs.readFileSync(path.join(ROOT, 'workflows', 'src', 'wazuh-ai-triage', 'build-llm-request.js'));
  const promptVersion = crypto.createHash('sha256').update(promptSource).digest('hex').slice(0, 12);
  loadNode('parse-score'); // fail early if a node file is missing

  const rows = [];
  for (const [file, label] of Object.entries(labels)) {
    if (file.startsWith('_')) continue;
    const alert = JSON.parse(fs.readFileSync(path.join(ROOT, 'samples', 'alerts', file), 'utf8'));
    const [sanitized] = await runNode('sanitize-validate', {
      env, items: [{ headers: { 'x-wazuh-token': SECRET }, body: alert }],
    });
    const item = { ...sanitized.json, duplicates_suppressed: 0, threat_intel: {} };
    const built = await runNode('build-llm-request', { env, item });
    const started = Date.now();
    let response;
    try {
      const res = await fetch(`${BASE_URL}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${API_KEY}` },
        body: JSON.stringify(built.json.llm_request),
        signal: AbortSignal.timeout(300000),
      });
      response = await res.json();
      if (!res.ok && !response.error) response = { error: { message: `HTTP ${res.status}` } };
    } catch (e) {
      response = { error: { message: String(e.message || e) } };
    }
    const latency = Date.now() - started;
    const scored = (await runNode('parse-score', { env, item: response, nodes: { 'Build LLM Request': built.json } })).json;
    const t = scored.triage;
    const sevIdx = SEVERITIES.indexOf(t.model_severity);
    const row = {
      sample: file,
      schema_ok: t.ai_ok,
      verdict: t.verdict,
      verdict_ok: t.ai_ok && label.verdict.includes(t.verdict),
      severity: t.model_severity,
      severity_ok: t.ai_ok && sevIdx >= SEVERITIES.indexOf(label.min_severity)
        && (!label.max_severity || sevIdx <= SEVERITIES.indexOf(label.max_severity)),
      block_ok: (scored.action === 'would_block') === label.block_expected,
      model_wants_block: t.model_wants_block,
      latency_ms: latency,
      error: t.ai_error || undefined,
    };
    rows.push(row);
    const mark = (ok) => (ok ? 'ok ' : 'BAD');
    console.log(`${file.padEnd(36)} schema ${mark(row.schema_ok)} verdict ${mark(row.verdict_ok)} ` +
      `severity ${mark(row.severity_ok)} block ${mark(row.block_ok)} ${String(latency).padStart(6)} ms` +
      (row.error ? `  (${row.error.slice(0, 80)})` : ''));
  }

  const count = (key) => rows.filter((r) => r[key]).length;
  const summary = {
    model: MODEL,
    base_url: BASE_URL,
    prompt_version: promptVersion,
    settings: { temperature: 0.1, max_tokens: Number(process.env.LLM_MAX_TOKENS) || 2048 },
    run_at: new Date().toISOString(),
    samples: rows.length,
    schema_valid: count('schema_ok'),
    verdict_ok: count('verdict_ok'),
    severity_ok: count('severity_ok'),
    block_ok: count('block_ok'),
    median_latency_ms: rows.map((r) => r.latency_ms).sort((a, b) => a - b)[Math.floor(rows.length / 2)],
    note: 'Smoke test on a handful of samples. Not an accuracy measure.',
  };
  console.log('\n' + JSON.stringify({ summary, rows }, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
