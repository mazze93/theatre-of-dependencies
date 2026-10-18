// Just enough semver to place an installed version inside an OSV range.
// Prerelease tags sort before their release, per semver §11; build metadata is ignored.

function parse(v) {
  const [core, pre] = String(v).replace(/^v/, '').split('+')[0].split(/-(.*)/s);
  const nums = core.split('.').map((n) => Number.parseInt(n, 10) || 0);
  while (nums.length < 3) nums.push(0);
  return { nums, pre: pre ? pre.split('.') : [] };
}

export function compare(a, b) {
  const A = parse(a), B = parse(b);
  for (let i = 0; i < 3; i++) if (A.nums[i] !== B.nums[i]) return A.nums[i] < B.nums[i] ? -1 : 1;
  if (!A.pre.length || !B.pre.length) return A.pre.length ? -1 : B.pre.length ? 1 : 0;
  for (let i = 0; i < Math.max(A.pre.length, B.pre.length); i++) {
    const x = A.pre[i], y = B.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny && +x !== +y) return +x < +y ? -1 : 1;
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// The lowest `fixed` event that closes the range containing `version`, or null
// when the advisory has no fix for this line (the break that is kept).
export function fixedFor(version, ranges) {
  let best = null;
  for (const r of ranges ?? []) {
    if (r.type !== 'SEMVER' && r.type !== 'ECOSYSTEM') continue;
    let introduced = null;
    for (const e of r.events ?? []) {
      if (e.introduced !== undefined) introduced = e.introduced;
      const end = e.fixed ?? e.last_affected;
      if (end === undefined || introduced === null) continue;
      const inside =
        (introduced === '0' || compare(version, introduced) >= 0) &&
        (e.fixed !== undefined ? compare(version, end) < 0 : compare(version, end) <= 0);
      if (inside && e.fixed !== undefined && (!best || compare(e.fixed, best) < 0)) best = e.fixed;
      introduced = null;
    }
  }
  return best;
}
