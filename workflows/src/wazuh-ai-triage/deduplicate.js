// Second dedup layer (the first one runs on the Wazuh side in custom-n8n.py).
// Two separate questions, same contract as custom-n8n.py:
//  1. Is this the same alert again (same event_key)? Then it is a re-delivery,
//     for example a retry after a lost HTTP answer. Drop it and do NOT count it.
//  2. Is it "the same thing" as an alert analysed in this window (same group_key)?
//     Then drop it and count it. The count is reported with the next alert of the
//     group that gets through, which happens only if another one arrives after
//     the window (there is no timer that sends a summary on its own).
// Alerts with no group_key (not enough data to tell events apart) are never grouped.
//
// Note: n8n saves this memory only after a run ends successfully, and only for
// production runs (not editor test runs). It is a best-effort filter, not storage.

const DEFAULT_WINDOW_SECONDS = 600;
const rawWindow = String($env.DEDUP_WINDOW_SECONDS ?? '').trim();
const WINDOW_MS = (/^\d{1,7}$/.test(rawWindow) ? Number(rawWindow) : DEFAULT_WINDOW_SECONDS) * 1000;
const EVENT_MEMORY_MS = 24 * 60 * 60 * 1000;

const store = $getWorkflowStaticData('global');
store.groups = store.groups || {};
store.events = store.events || {};
delete store.fingerprints; // old format (before the event/group split)
const now = Date.now();

// Forget old entries so the store stays small. Groups that still hold a count are
// kept for up to a day, so the count can be reported.
for (const [key, entry] of Object.entries(store.groups)) {
  const age = now - entry.last_forwarded;
  if (age > EVENT_MEMORY_MS || (entry.suppressed === 0 && age > Math.max(WINDOW_MS * 2, 60000))) {
    delete store.groups[key];
  }
}
for (const [key, seen] of Object.entries(store.events)) {
  if (now - seen > EVENT_MEMORY_MS) delete store.events[key];
}

const out = [];
const items = $input.all();
for (let i = 0; i < items.length; i++) {
  const a = items[i].json;

  if (a.event_key) {
    if (store.events[a.event_key]) continue; // re-delivery of an alert we already took
    store.events[a.event_key] = now;
  }

  let suppressedBefore = 0;
  if (a.group_key && WINDOW_MS > 0) {
    const entry = store.groups[a.group_key];
    if (entry && now - entry.last_forwarded < WINDOW_MS) {
      entry.suppressed += 1;
      continue;
    }
    suppressedBefore = entry ? entry.suppressed : 0;
    store.groups[a.group_key] = { last_forwarded: now, suppressed: 0 };
  }

  out.push({
    json: {
      ...a,
      duplicates_suppressed: suppressedBefore + (a.edge_duplicates_suppressed || 0),
    },
    pairedItem: { item: i },
  });
}
return out;
