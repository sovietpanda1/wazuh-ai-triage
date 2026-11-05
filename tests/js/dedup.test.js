'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { runNode } = require('./harness');

const SECRET = 'test-secret-0123456789'; // gitleaks:allow (test placeholder)

async function prepare(alert) {
  const out = await runNode('sanitize-validate', {
    env: { WEBHOOK_SECRET: SECRET }, items: [{ headers: { 'x-wazuh-token': SECRET }, body: alert }],
  });
  return out[0].json;
}

const fim = (id, path) => ({
  id, manager: { name: 'mgr' }, agent: { id: '000' }, rule: { id: '550', level: 7 }, syscheck: { path, event: 'modified' },
});
const ssh = (id, level = 10) => ({
  id, manager: { name: 'mgr' }, agent: { id: '000' }, rule: { id: '5712', level }, data: { srcip: '8.8.8.8' },
});

function dedupRunner(env = { DEDUP_WINDOW_SECONDS: '600' }) {
  const staticData = {};
  return async (alert) => {
    const out = await runNode('deduplicate', { env, items: [await prepare(alert)], staticData });
    return out.map((o) => o.json);
  };
}

test('two different files on the same agent and rule both pass', async () => {
  const run = dedupRunner();
  assert.equal((await run(fim('1', '/etc/ssh/sshd_config'))).length, 1);
  assert.equal((await run(fim('2', '/etc/sudoers'))).length, 1);
});

test('the same event id sent again is dropped and not counted', async () => {
  const run = dedupRunner({ DEDUP_WINDOW_SECONDS: '0' });
  assert.equal((await run(ssh('7.7'))).length, 1);
  assert.equal((await run(ssh('7.7'))).length, 0);
  assert.equal((await run(ssh('7.7'))).length, 0);
});

test('similar alerts in the window are dropped and counted; a retry is not counted', async () => {
  const staticData = {};
  const env = { DEDUP_WINDOW_SECONDS: '600' };
  const run = async (alert) => (await runNode('deduplicate', { env, items: [await prepare(alert)], staticData })).map((o) => o.json);
  assert.equal((await run(ssh('a'))).length, 1);
  assert.equal((await run(ssh('b'))).length, 0);
  assert.equal((await run(ssh('b'))).length, 0); // re-delivery of b
  assert.equal((await run(ssh('c'))).length, 0);
  // pretend the window has passed
  for (const entry of Object.values(staticData.groups)) entry.last_forwarded -= 601 * 1000;
  const out = await run(ssh('d'));
  assert.equal(out.length, 1);
  assert.equal(out[0].duplicates_suppressed, 2);
});

test('a higher level is not swallowed by the earlier window', async () => {
  const run = dedupRunner();
  assert.equal((await run(ssh('a', 10))).length, 1);
  assert.equal((await run(ssh('b', 12))).length, 1);
});

test('alerts without a group key are never grouped', async () => {
  const run = dedupRunner();
  const bare = (id) => ({ id, agent: { id: '000' }, rule: { id: '510', level: 7 } });
  assert.equal((await run(bare('1'))).length, 1);
  assert.equal((await run(bare('2'))).length, 1);
});

test('an invalid DEDUP_WINDOW_SECONDS falls back to 600 instead of disabling dedup', async () => {
  const run = dedupRunner({ DEDUP_WINDOW_SECONDS: 'ten minutes' });
  assert.equal((await run(ssh('a'))).length, 1);
  assert.equal((await run(ssh('b'))).length, 0);
});

test('edge counts from custom-n8n.py are added', async () => {
  const run = dedupRunner();
  const a = ssh('a');
  a.wazuh_n8n = { duplicates_suppressed: 19 };
  assert.equal((await run(a))[0].duplicates_suppressed, 19);
});
