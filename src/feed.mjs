// Turn OSV advisories into food: one source per vulnerable package, weighted by
// the severity of what it carries.

import { severityOf } from './severity.mjs';
import { fixedFor, compare } from './semver.mjs';

export async function gatherFood(terrain, osv, { prod = false } = {}) {
  const candidates = terrain.nodes.filter((n) => n.id !== 0 && !(prod && n.dev));
  const hits = await osv.affecting(candidates);
  const refs = [...hits.values()].flat();
  const records = await osv.records(refs);

  const food = [];
  for (const [nodeId, vulns] of hits) {
    if (!vulns.length) continue;
    const node = terrain.nodes[nodeId];
    const seen = new Set(), advisories = [];
    for (const { id } of vulns) {
      const rec = records.get(id);
      if (!rec || rec.withdrawn) continue;
      const names = [rec.id, ...(rec.aliases ?? [])];
      if (names.some((x) => seen.has(x))) continue;   // GHSA and CVE for the same flaw
      names.forEach((x) => seen.add(x));
      const ranges = (rec.affected ?? [])
        .filter((a) => a.package?.name === node.name && (!node.ecosystem || a.package?.ecosystem === node.ecosystem))
        .flatMap((a) => a.ranges ?? []);
      const sev = severityOf(rec);
      advisories.push({
        id: rec.id, aliases: (rec.aliases ?? []).filter((a) => a.startsWith('CVE-')),
        summary: (rec.summary ?? rec.details ?? '').split('\n')[0].slice(0, 120),
        score: sev.score, label: sev.label, fixed: fixedFor(node.version, ranges),
      });
    }
    if (!advisories.length) continue;
    advisories.sort((a, b) => b.score - a.score);
    // Weight: the worst advisory counts fully, each further one adds a quarter —
    // six moderate bugs in one package should outweigh one, but not six-fold.
    const w = advisories.reduce((s, a, i) => s + (i === 0 ? a.score : a.score * 0.25), 0) / 10;
    const fixes = advisories.map((a) => a.fixed);
    const fixed = fixes.includes(null) ? null : fixes.reduce((m, f) => (compare(f, m) > 0 ? f : m));
    food.push({ node: nodeId, name: node.name, version: node.version, w, advisories,
      fixed, partialFix: fixes.includes(null) && fixes.some(Boolean)
        ? fixes.filter(Boolean).reduce((m, f) => (compare(f, m) > 0 ? f : m)) : null });
  }
  food.sort((a, b) => b.w - a.w);
  return food;
}
