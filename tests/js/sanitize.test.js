'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { runNode } = require('./harness');

const ROOT = path.join(__dirname, '..', '..');
const SECRET = 'test-secret-0123456789'; // gitleaks:allow (test placeholder)
const ENV = { WEBHOOK_SECRET: SECRET, ABUSEIPDB_API_KEY: 'k' };
const sample = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, 'samples', 'alerts', name), 'utf8'));

async function sanitize(body, { env = ENV, token = SECRET } = {}) {
  const headers = token === null ? {} : { 'x-wazuh-token': token };
  const out = await runNode('sanitize-validate', { env, items: [{ headers, body }] });
  assert.equal(out.length, 1);
  return out[0].json;
}

const alertWithIp = (srcip) => ({
  id: '1.1', manager: { name: 'mgr' }, agent: { id: '000', name: 'host' },
  rule: { id: '5712', level: 10, description: 'test' }, data: { srcip },
});

// ---------- F3: fail closed, clear HTTP answers ----------

test('empty WEBHOOK_SECRET refuses every request (503), even with no token', async () => {
  const r = await sanitize(sample('01-ssh-bruteforce.json'), { env: {}, token: null });
  assert.equal(r.accepted, false);
  assert.equal(r.http_status, 503);
});

test('missing or wrong token gets 401', async () => {
  assert.equal((await sanitize(sample('01-ssh-bruteforce.json'), { token: null })).http_status, 401);
  assert.equal((await sanitize(sample('01-ssh-bruteforce.json'), { token: 'wrong' })).http_status, 401);
  assert.equal((await sanitize(sample('01-ssh-bruteforce.json'), { token: SECRET + 'x' })).http_status, 401);
});

test('malformed body gets 400', async () => {
  for (const body of [null, [], 'text', { rule: {} }, { rule: { id: '1', level: 'high' } }, { rule: { id: '1', level: 99 } }]) {
    assert.equal((await sanitize(body)).http_status, 400, JSON.stringify(body));
  }
});

test('a valid alert is accepted with 202 and the ACK says it is not a delivery receipt', async () => {
  const r = await sanitize(sample('01-ssh-bruteforce.json'));
  assert.equal(r.accepted, true);
  assert.equal(r.http_status, 202);
  assert.match(r.http_body.note, /not a delivery receipt/);
});

test('a short secret is reported as a config warning', async () => {
  const r = await sanitize(sample('01-ssh-bruteforce.json'), { env: { WEBHOOK_SECRET: 'short' }, token: 'short' });
  assert.ok(r.config_warnings.some((w) => w.includes('shorter')));
});

// ---------- F4: IP parsing and global/public classification ----------

test('not-public addresses are recognised (IPv4 and IPv6)', async () => {
  const notPublic = [
    '0:0:0:0:0:0:0:1', '::1', '::', 'ff02::1', '::ffff:7f00:1', '::ffff:127.0.0.1', '::ffff:10.1.2.3',
    'fe80::1', 'fd00::1', '2001:db8::1', '3fff::1', '64:ff9b::a00:1',
    '127.0.0.1', '10.0.0.1', '172.16.5.4', '192.168.1.1', '100.64.0.1', '169.254.1.1',
    '192.0.2.77', '198.51.100.23', '203.0.113.45', '198.18.0.1', '192.0.0.8', '224.0.0.1', '255.255.255.255', '0.1.2.3',
  ];
  for (const ip of notPublic) {
    const r = await sanitize(alertWithIp(ip));
    assert.notEqual(r.srcip, '', `${ip} should parse`);
    assert.equal(r.srcip_is_public, false, `${ip} must not be public`);
    assert.equal(r.enrich, false, `${ip} must not be looked up`);
  }
});

test('global addresses are public', async () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2a00:1450:4001::1', '::ffff:8.8.8.8', '64:ff9b::808:808']) {
    const r = await sanitize(alertWithIp(ip));
    assert.equal(r.srcip_is_public, true, `${ip} should be public`);
  }
});

test('malformed addresses are rejected, but the alert still goes on', async () => {
  for (const ip of ['::::', ':::1', '1:2:3:4:5:6:7:8:9', '1::2::3', '12345::1', '256.1.1.1', '01.2.3.4', 'g::1',
    '1.2.3', '::1%eth0', '1:2:3:4:5:6:7::8', 'abc', ' ', '1.2.3.4/24']) {
    const r = await sanitize(alertWithIp(ip));
    assert.equal(r.accepted, true, ip);
    assert.equal(r.srcip, '', `${JSON.stringify(ip)} must be rejected`);
    assert.equal(r.srcip_is_public, false);
  }
});

test('IPv6 addresses are canonicalised', async () => {
  assert.equal((await sanitize(alertWithIp('2001:0DB8:0000:0000:0000:0000:0000:0001'))).srcip, '2001:db8::1');
  assert.equal((await sanitize(alertWithIp('2606:4700:4700:0:0:0:0:1111'))).srcip, '2606:4700:4700::1111');
  assert.equal((await sanitize(alertWithIp('1:0:0:1:0:0:0:1'))).srcip, '1:0:0:1::1');
});

test('whitelist CIDRs work for IPv4, IPv6 and IPv4-mapped IPv6', async () => {
  const env = { ...ENV, WHITELIST_CIDRS: '8.8.8.0/24, 2606:4700::/32, 9.9.9.9, not-a-cidr, 1.2.3.4/33' };
  assert.equal((await sanitize(alertWithIp('8.8.8.8'), { env })).srcip_whitelisted, true);
  assert.equal((await sanitize(alertWithIp('8.8.9.8'), { env })).srcip_whitelisted, false);
  assert.equal((await sanitize(alertWithIp('2606:4700:4700::1111'), { env })).srcip_whitelisted, true);
  assert.equal((await sanitize(alertWithIp('2606:4701::1'), { env })).srcip_whitelisted, false);
  assert.equal((await sanitize(alertWithIp('::ffff:8.8.8.1'), { env })).srcip_whitelisted, true);
  assert.equal((await sanitize(alertWithIp('9.9.9.9'), { env })).srcip_whitelisted, true);
  const r = await sanitize(alertWithIp('9.9.9.10'), { env });
  assert.equal(r.srcip_whitelisted, false);
  assert.equal(r.config_warnings.filter((w) => w.includes('WHITELIST_CIDRS')).length, 2);
});

test('documentation (TEST-NET) addresses in the samples are not public', async () => {
  for (const name of ['01-ssh-bruteforce.json', '02-web-sql-injection.json', '04-prompt-injection-username.json']) {
    const r = await sanitize(sample(name));
    assert.equal(r.srcip_is_public, false, name);
  }
});

// ---------- F1: dedup keys, same contract as custom-n8n.py ----------

test('dedup keys match the shared contract fixtures', async () => {
  const { cases } = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', 'dedup_cases.json'), 'utf8'));
  for (const c of cases) {
    const r = await sanitize(c.alert);
    assert.equal(r.event_key, c.event_key, c.name);
    assert.equal(r.group_key, c.group_key, c.name);
  }
});

// ---------- F7: structured fields per alert family ----------

test('FIM alerts keep the syscheck fields', async () => {
  const r = await sanitize(sample('03-fim-sshd-config.json'));
  assert.equal(r.syscheck.path, '/etc/ssh/sshd_config');
  assert.equal(r.syscheck.event, 'modified');
  assert.deepEqual(r.syscheck.changed_attributes, ['size', 'mtime', 'md5', 'sha1', 'sha256']);
  assert.equal(r.syscheck.sha256_after.length, 64);
  assert.equal('diff' in r.syscheck, false);
});

test('Windows alerts get IP and user from the nested event data', async () => {
  const r = await sanitize(sample('05-windows-failed-logon.json'));
  assert.equal(r.srcip, '192.168.1.50');
  assert.equal(r.srcip_field, 'data.win.eventdata.ipAddress');
  assert.equal(r.dstuser, 'jdoe');
  assert.equal(r.windows.event_id, '4625');
  assert.equal(r.windows.logon_type, '3');
  assert.equal(r.windows.target_user, 'jdoe');
});

test('cut fields are recorded and control characters removed', async () => {
  const a = alertWithIp('8.8.8.8');
  a.full_log = 'x'.repeat(5000);
  a.data.srcuser = 'ad\u0000min\u001b';
  const r = await sanitize(a);
  assert.equal(r.full_log.length, 1500);
  assert.deepEqual(r.truncated_fields, ['full_log']);
  assert.equal(r.srcuser, 'admin');
});
