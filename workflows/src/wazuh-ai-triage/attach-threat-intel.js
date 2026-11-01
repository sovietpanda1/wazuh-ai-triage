// Merge the AbuseIPDB answer back into the alert.
// The lookup node continues on errors, so a failed lookup never stops the pipeline.

const alert = $('Deduplicate').item.json;
const response = $input.item.json || {};
const d = response.data;

let abuseipdb;
if (d && typeof d.abuseConfidenceScore === 'number') {
  abuseipdb = {
    score: d.abuseConfidenceScore,
    total_reports: d.totalReports ?? null,
    country: String(d.countryCode || ''),
    isp: String(d.isp || '').slice(0, 100),
    usage_type: String(d.usageType || '').slice(0, 60),
    is_tor: Boolean(d.isTor),
    last_reported_at: String(d.lastReportedAt || ''),
  };
} else {
  const err = response.error;
  abuseipdb = { error: String((err && (err.message || err)) || 'lookup failed').slice(0, 200) };
}

return { json: { ...alert, threat_intel: { abuseipdb } } };
