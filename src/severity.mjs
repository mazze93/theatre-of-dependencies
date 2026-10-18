// Severity → weight. The weight is how much "food" a vulnerability is for the
// organism: a critical advisory pulls harder than a low one.
//
// Preference order: a CVSS v3.x vector (computed exactly, per the FIRST spec),
// then the advisory database's own label, then a neutral default.

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

// CVSS v3.1 §7.4 Roundup: smallest one-decimal number >= x, float-safe.
function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvss3Score(vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = Object.fromEntries(
    vector.split('/').slice(1).map((kv) => kv.split(':')),
  );
  const scopeChanged = m.S === 'C';
  const av = W.AV[m.AV], ac = W.AC[m.AC], ui = W.UI[m.UI];
  const pr = (scopeChanged ? W.PR_C : W.PR_U)[m.PR];
  const c = W.CIA[m.C], i = W.CIA[m.I], a = W.CIA[m.A];
  if ([av, ac, ui, pr, c, i, a].some((v) => v === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploit = 8.22 * av * ac * pr * ui;
  return scopeChanged
    ? roundup(Math.min(1.08 * (impact + exploit), 10))
    : roundup(Math.min(impact + exploit, 10));
}

const LABEL_SCORE = { CRITICAL: 9.5, HIGH: 7.5, MODERATE: 5.0, MEDIUM: 5.0, LOW: 2.5 };

export function labelFor(score) {
  if (score == null) return 'UNKNOWN';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MODERATE';
  if (score > 0) return 'LOW';
  return 'NONE';
}

// Returns { score, label, source } for an OSV record.
export function severityOf(record) {
  for (const s of record.severity ?? []) {
    if (s.type === 'CVSS_V3') {
      const score = cvss3Score(s.score);
      if (score != null) return { score, label: labelFor(score), source: 'cvss3' };
    }
  }
  const raw = record.database_specific?.severity;
  if (typeof raw === 'string' && LABEL_SCORE[raw.toUpperCase()]) {
    const score = LABEL_SCORE[raw.toUpperCase()];
    return { score, label: labelFor(score), source: 'label' };
  }
  return { score: 4.0, label: 'UNKNOWN', source: 'default' };
}
