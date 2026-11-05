'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { runNode } = require('./harness');

const triaged = { alert_id: '1.1', rule: { id: '5712' }, message: 'hi' };
const run = (reply, env = {}) => runNode('result', { env, item: reply, nodes: { 'Parse & Score': triaged } });

test('a sent message is recorded', async () => {
  assert.equal((await run({ ok: true })).json.notification, 'sent');
});

test('a failed Telegram send fails the execution instead of being swallowed', async () => {
  await assert.rejects(run({ error: { message: 'Bad Request: chat not found' } }), /not sent: Bad Request: chat not found/);
  await assert.rejects(run({}), /not sent/);
});

test('Telegram can be turned off on purpose', async () => {
  assert.match((await run(triaged, { TELEGRAM_ENABLED: 'false' })).json.notification, /disabled/);
});
