// Sanitize & validate incoming Wazuh alerts.
// - Fails closed: if WEBHOOK_SECRET is not set, every request is refused (503).
//   A wrong or missing X-Wazuh-Token gets 401, a body that is not a Wazuh alert gets 400.
//   The "Acknowledge" node sends that HTTP answer right away; only accepted alerts go on.
// - Keeps only the fields the pipeline needs, per alert family (FIM, Windows, network),
//   strips control characters, caps lengths and records which fields were cut.
// - Parses IPv4/IPv6 addresses properly and decides whether an address is global
//   (public). Only global addresses are looked up or can get a block recommendation.
// - Builds the dedup keys (same contract as wazuh/integrations/custom-n8n.py,
//   checked by tests/fixtures/dedup_cases.json).

const MIN_SECRET_LENGTH = 16;
const SECRET = String($env.WEBHOOK_SECRET || '').trim();
const HAS_ABUSEIPDB_KEY = String($env.ABUSEIPDB_API_KEY || '').trim() !== '';

// ---------- IP addresses ----------

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HEXTET_RE = /^[0-9a-fA-F]{1,4}$/;

function parseIPv4(text) {
  if (!IPV4_RE.test(text)) return null;
  const value = text.split('.').reduce((acc, octet) => (acc << 8n) + BigInt(octet), 0n);
  return { version: 4, value };
}

function parseIPv6(text) {
  if (!text.includes(':') || text.length > 45) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parseSide = (side, allowV4Tail) => {
    if (side === '') return [];
    const parts = side.split(':');
    const groups = [];
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (allowV4Tail && i === parts.length - 1 && part.includes('.')) {
        const v4 = parseIPv4(part);
        if (!v4) return null;
        groups.push(Number(v4.value >> 16n), Number(v4.value & 0xffffn));
      } else if (HEXTET_RE.test(part)) {
        groups.push(parseInt(part, 16));
      } else {
        return null;
      }
    }
    return groups;
  };
  let groups;
  if (halves.length === 2) {
    const left = parseSide(halves[0], false);
    const right = parseSide(halves[1], true);
    if (!left || !right || left.length + right.length > 7) return null;
    groups = [...left, ...new Array(8 - left.length - right.length).fill(0), ...right];
  } else {
    groups = parseSide(text, true);
    if (!groups || groups.length !== 8) return null;
  }
  const value = groups.reduce((acc, g) => (acc << 16n) + BigInt(g), 0n);
  return { version: 6, value };
}

function parseIp(text) {
  const s = String(text || '').trim();
  return parseIPv4(s) || parseIPv6(s);
}

// Same output as Python's ipaddress module: "a.b.c.d", or lower-case IPv6 with the
// longest run (2+ groups) of zeros shortened to "::".
function formatIp(ip) {
  if (ip.version === 4) {
    return [24n, 16n, 8n, 0n].map((s) => String((ip.value >> s) & 0xffn)).join('.');
  }
  const groups = [];
  for (let s = 112n; s >= 0n; s -= 16n) groups.push(Number((ip.value >> s) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

function canonicalIp(text) {
  const ip = parseIp(text);
  return ip ? formatIp(ip) : '';
}

// ::ffff:a.b.c.d is an IPv4 address in IPv6 clothing: judge it as IPv4.
const MAPPED_PREFIX = 0xffffn << 32n;
function effectiveIp(ip) {
  if (ip.version === 6 && ip.value >> 32n === 0xffffn) return { version: 4, value: ip.value - MAPPED_PREFIX };
  return ip;
}

function parseCidr(text) {
  const [base, bits, extra] = String(text).trim().split('/');
  if (extra !== undefined) return null;
  const ip = parseIp(base);
  if (!ip) return null;
  const width = ip.version === 4 ? 32 : 128;
  if (bits !== undefined && !/^\d{1,3}$/.test(bits)) return null;
  const prefix = bits === undefined ? width : Number(bits);
  if (prefix > width) return null;
  const shift = BigInt(width - prefix);
  return { version: ip.version, network: (ip.value >> shift) << shift, shift, text: String(text).trim() };
}

function inCidr(ip, cidr) {
  return ip.version === cidr.version && (ip.value >> cidr.shift) << cidr.shift === cidr.network;
}

// Not globally routable (IANA special-purpose registries, plus multicast).
const NON_GLOBAL_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
].map(parseCidr);
const NON_GLOBAL_V6 = [
  '::/128', '::1/128', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32', '2002::/16',
  '3fff::/20', '5f00::/16', 'fc00::/7', 'fe80::/10', 'ff00::/8',
].map(parseCidr);
const GLOBAL_UNICAST_V6 = parseCidr('2000::/3');
const NAT64_V6 = parseCidr('64:ff9b::/96');

function isGlobal(ipIn) {
  let ip = effectiveIp(ipIn);
  if (ip.version === 6 && inCidr(ip, NAT64_V6)) ip = { version: 4, value: ip.value & 0xffffffffn };
  if (ip.version === 4) return !NON_GLOBAL_V4.some((c) => inCidr(ip, c));
  if (!inCidr(ip, GLOBAL_UNICAST_V6)) return false;
  return !NON_GLOBAL_V6.some((c) => inCidr(ip, c));
}

const configWarnings = [];
if (SECRET && SECRET.length < MIN_SECRET_LENGTH) configWarnings.push(`WEBHOOK_SECRET is shorter than ${MIN_SECRET_LENGTH} characters`);
const WHITELIST = [];
for (const entry of String($env.WHITELIST_CIDRS || '').split(',').map((s) => s.trim()).filter(Boolean)) {
  const cidr = parseCidr(entry);
  if (cidr) WHITELIST.push(cidr);
  else configWarnings.push(`WHITELIST_CIDRS: ignored invalid entry "${entry.slice(0, 60)}"`);
}

function isWhitelisted(ipIn) {
  const candidates = [ipIn, effectiveIp(ipIn)];
  return WHITELIST.some((c) => candidates.some((ip) => inCidr(ip, c)));
}

// ---------- strings ----------

const CONTROL_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F]/g;
const truncated = new Set();

function clean(value, max = 300, field = '') {
  if (value === undefined || value === null) return '';
  const text = String(typeof value === 'object' ? JSON.stringify(value) : value).replace(CONTROL_CHARS, '');
  if (text.length > max) {
    if (field) truncated.add(field);
    return text.slice(0, max);
  }
  return text;
}

function list(value, maxItems = 10, maxLen = 60, field = '') {
  const arr = Array.isArray(value) ? value : value ? [value] : [];
  if (arr.length > maxItems && field) truncated.add(field);
  return arr.slice(0, maxItems).map((v) => clean(v, maxLen, field));
}

// Constant-time string comparison, so the secret cannot be guessed byte by byte.
function safeEqual(a, b) {
  const x = String(a);
  const y = String(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  }
  return diff === 0;
}

// ---------- dedup keys (contract shared with custom-n8n.py) ----------
// event_key: one Wazuh alert (manager + agent + alert id). A copy with the same key is
//   a re-delivery, never a new attack, and is dropped without being counted.
// group_key: alerts that are "the same thing" and may be grouped in one window:
//   manager + agent + rule + level + a family-specific subject. When there is no
//   subject that safely tells events apart, group_key is null and nothing is grouped.

function keyPart(value) {
  return String(value === undefined || value === null ? '' : value).replace(CONTROL_CHARS, '').trim().slice(0, 256);
}

function dedupKeys(a) {
  const rule = a.rule || {};
  const agent = a.agent || {};
  const data = a.data || {};
  const manager = keyPart((a.manager && a.manager.name) || '-') || '-';
  const agentKey = keyPart(agent.id || agent.name || '-') || '-';
  const alertId = keyPart(a.id);
  const eventKey = alertId ? ['evt', manager, agentKey, alertId].join('|') : null;

  const sys = a.syscheck || {};
  const win = (data.win && data.win.eventdata) || null;
  let subject = '';
  if (keyPart(sys.path)) {
    subject = `fim:${keyPart(sys.path)}:${keyPart(sys.event)}`;
  } else if (win) {
    const ip = canonicalIp(win.ipAddress) || canonicalIp(data.srcip) || canonicalIp(data.src_ip);
    const user = keyPart(win.targetUserName).toLowerCase();
    if (ip || user) subject = `win:${ip}:${user}:${keyPart(win.logonType)}`;
  } else {
    const ip = canonicalIp(data.srcip) || canonicalIp(data.src_ip);
    if (ip) subject = `ip:${ip}`;
  }
  const groupKey = subject
    ? ['grp', manager, agentKey, keyPart(rule.id) || '?', keyPart(rule.level) || '?', subject].join('|')
    : null;
  return { event_key: eventKey, group_key: groupKey };
}

// ---------- normalizers per alert family ----------

function guessOs(alert) {
  const hay = `${alert.location || ''} ${(alert.decoder && alert.decoder.name) || ''}`.toLowerCase();
  if (hay.includes('eventchannel') || hay.includes('windows')) return 'windows';
  if (hay.includes('macos') || hay.includes('unified')) return 'macos';
  return 'linux';
}

function normalizeSyscheck(s) {
  if (!s || typeof s !== 'object' || !s.path) return null;
  const out = {
    path: clean(s.path, 400, 'syscheck.path'),
    event: clean(s.event, 20),
    mode: clean(s.mode, 20),
    changed_attributes: list(s.changed_attributes, 15, 30, 'syscheck.changed_attributes'),
  };
  for (const f of ['size_before', 'size_after', 'perm_before', 'perm_after', 'uname_before', 'uname_after',
    'gname_after', 'mtime_after', 'md5_after', 'sha1_after', 'sha256_before', 'sha256_after']) {
    if (s[f] !== undefined && s[f] !== null && s[f] !== '') out[f] = clean(s[f], 100, `syscheck.${f}`);
  }
  // who-data (only with whodata mode): who changed the file and with what program
  if (s.audit && typeof s.audit === 'object') {
    out.audit_user = clean(s.audit.user && s.audit.user.name, 100);
    out.audit_process = clean(s.audit.process && s.audit.process.name, 200, 'syscheck.audit.process');
  }
  // syscheck.diff (file content) is left out on purpose: it can hold secrets.
  return out;
}

function normalizeWindows(win) {
  if (!win || typeof win !== 'object') return null;
  const ev = win.eventdata || {};
  const sys = win.system || {};
  const rawIp = clean(ev.ipAddress, 64).trim();
  return {
    event_id: clean(sys.eventID, 10),
    channel: clean(sys.channel, 60),
    target_user: clean(ev.targetUserName, 100),
    target_domain: clean(ev.targetDomainName, 100),
    subject_user: clean(ev.subjectUserName, 100),
    logon_type: clean(ev.logonType, 4),
    ip: canonicalIp(rawIp),
    workstation: clean(ev.workstationName, 100),
    process_name: clean(ev.processName, 200, 'windows.process_name'),
    status: clean(ev.status, 20),
    sub_status: clean(ev.subStatus, 20),
    failure_reason: clean(ev.failureReason, 100),
  };
}

// ---------- main ----------

function reject(i, status, error) {
  return { json: { accepted: false, http_status: status, http_body: { accepted: false, error } }, pairedItem: { item: i } };
}

const out = [];
const items = $input.all();
for (let i = 0; i < items.length; i++) {
  truncated.clear();
  const headers = items[i].json.headers || {};
  if (!SECRET) {
    out.push(reject(i, 503, 'webhook is not configured (WEBHOOK_SECRET is empty)'));
    continue;
  }
  if (!safeEqual(headers['x-wazuh-token'] || '', SECRET)) {
    out.push(reject(i, 401, 'missing or wrong X-Wazuh-Token'));
    continue;
  }

  const a = items[i].json.body;
  if (!a || typeof a !== 'object' || Array.isArray(a)) {
    out.push(reject(i, 400, 'body must be a JSON object'));
    continue;
  }
  const rule = a.rule || {};
  const data = a.data || {};
  const agent = a.agent || {};
  const level = Number(rule.level);
  if (!rule.id || !Number.isInteger(level) || level < 0 || level > 16) {
    out.push(reject(i, 400, 'not a Wazuh alert (rule.id and a numeric rule.level are required)'));
    continue;
  }

  const windows = normalizeWindows(data.win);
  const syscheck = normalizeSyscheck(a.syscheck);

  // Source IP, with the field it came from (provenance).
  let srcip = '';
  let srcipField = '';
  for (const [field, value] of [['data.srcip', data.srcip], ['data.src_ip', data.src_ip],
    ['data.win.eventdata.ipAddress', windows && windows.ip]]) {
    const ip = canonicalIp(clean(value, 64));
    if (ip) { srcip = ip; srcipField = field; break; }
  }
  const parsed = srcip ? parseIp(srcip) : null;
  const srcipIsPublic = parsed !== null && isGlobal(parsed);
  const agentIp = canonicalIp(clean(agent.ip, 64));
  const keys = dedupKeys(a);

  const record = {
    accepted: true,
    http_status: 202,
    http_body: { accepted: true, alert_id: clean(a.id, 64), note: 'queued for analysis; this is not a delivery receipt' },
    alert_id: clean(a.id, 64),
    timestamp: clean(a.timestamp, 40),
    received_at: new Date().toISOString(),
    manager: clean(a.manager && a.manager.name, 100),
    rule: {
      id: clean(rule.id, 16),
      level,
      description: clean(rule.description, 300, 'rule.description'),
      groups: list(rule.groups, 10, 60, 'rule.groups'),
      firedtimes: Number(rule.firedtimes) || null,
      mitre: {
        ids: list(rule.mitre && rule.mitre.id),
        tactics: list(rule.mitre && rule.mitre.tactic),
        techniques: list(rule.mitre && rule.mitre.technique),
      },
    },
    agent: {
      id: clean(agent.id, 16),
      name: clean(agent.name, 100),
      ip: agentIp,
    },
    os_hint: guessOs(a),
    srcip,
    srcip_field: srcipField,
    srcip_is_public: srcipIsPublic,
    srcip_whitelisted: parsed !== null && isWhitelisted(parsed),
    srcport: clean(data.srcport, 8),
    srcuser: clean(data.srcuser || data.user, 100, 'srcuser'),
    dstuser: clean(data.dstuser || (windows && windows.target_user), 100, 'dstuser'),
    url: clean(data.url, 300, 'url'),
    location: clean(a.location, 200, 'location'),
    syscheck,
    windows,
    full_log: clean(a.full_log, 1500, 'full_log'),
    enrich: srcipIsPublic && HAS_ABUSEIPDB_KEY,
    event_key: keys.event_key,
    group_key: keys.group_key,
    // repeats already dropped on the Wazuh side by custom-n8n.py
    edge_duplicates_suppressed: Math.max(0, Math.floor(Number(a.wazuh_n8n && a.wazuh_n8n.duplicates_suppressed) || 0)),
    replayed: Boolean(a.wazuh_n8n && a.wazuh_n8n.replayed === true),
    config_warnings: configWarnings,
  };
  record.truncated_fields = [...truncated];
  out.push({ json: record, pairedItem: { item: i } });
}
return out;
