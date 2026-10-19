// From a converged organism to an upgrade ritual: which direct dependencies to
// act on, in what order, and exactly how much vulnerable surface each act closes.
//
// Coverage is computed exactly, not read off the organism: an advisory is closed
// by a set of acts S only if EVERY direct dependency it can enter through is in S.
// The organism proposes; the cut verifies. Where they disagree, the report says so.

import { ancestorsOf } from './physarum.mjs';
import { compare } from './semver.mjs';

export const STATES = [
  { min: 0.92, key: 'closed', label: 'CLOSED', note: 'healthy' },
  { min: 0.6, key: 'half', label: 'HALF-OPEN', note: 'thin' },
  { min: -1, key: 'open', label: 'OPEN', note: 'fragmented' },
];
export const stateFor = (cov) => STATES.find((s) => cov >= s.min);

export function stageRitual(terrain, food, organism, { maxActs = 7, backbone = 0.05 } = {}) {
  const { nodes, edges } = terrain;
  const n = nodes.length;
  const rootEdges = edges.map((e, i) => [e, i]).filter(([[a]]) => a === 0);
  const direct = new Set(rootEdges.map(([[, b]]) => b));

  // carriers(v) = the direct dependencies v can reach the project through.
  const carriers = new Map(), ancestors = new Map();
  for (const f of food) {
    const anc = ancestorsOf(n, edges, f.node, organism.live);
    ancestors.set(f.node, anc);
    // A vulnerable direct dependency is closed by bumping it — every other parent
    // that dedupes onto the same hoisted copy moves with it.
    carriers.set(f.node, direct.has(f.node) ? [f.node] : [...direct].filter((d) => anc[d]));
  }

  const total = food.reduce((s, f) => s + f.w, 0);
  const fixable = food.filter((f) => f.fixed).reduce((s, f) => s + f.w, 0);

  const flux = new Map(rootEdges.map(([[, b], i]) => [b, organism.Q[i]]));
  const tube = new Map(rootEdges.map(([[, b], i]) => [b, organism.D[i]]));
  const order = [...direct].filter((d) => (flux.get(d) ?? 0) > 1e-9).sort((a, b) => flux.get(b) - flux.get(a));

  const coverage = (set) => {
    let w = 0;
    for (const f of food) if (f.fixed && carriers.get(f.node).every((c) => set.has(c))) w += f.w;
    return total ? w / total : 1;
  };

  // The organism's own answer: entrances whose tube survived as backbone, by flux.
  const chosen = order.filter((d) => tube.get(d) >= backbone).slice(0, maxActs);
  const acts = [], picked = new Set();
  for (const d of chosen) {
    picked.add(d);
    acts.push(makeAct(d, picked));
  }

  // A second opinion: exact greedy cut over the same budget. If it closes more,
  // the organism's consolidation hid a shared entrance; we report it, we don't hide it.
  const greedy = new Set();
  for (let k = 0; k < acts.length; k++) {
    let best = null, bestCov = coverage(greedy);
    for (const d of order) {
      if (greedy.has(d)) continue;
      const c = coverage(new Set([...greedy, d]));
      if (c > bestCov + 1e-12 || (best === null && c >= bestCov)) { best = d; bestCov = c; }
    }
    if (best == null) break;
    greedy.add(best);
  }

  function makeAct(d, set) {
    const carried = food.filter((f) => carriers.get(f.node).includes(d));
    const items = carried.map((f) => ({
      ...f, path: pathTo(edges, organism, d, f.node, ancestors.get(f.node)),
      sharedWith: carriers.get(f.node).filter((c) => c !== d).map((c) => nodes[c].name),
    }));
    return {
      root: d, name: nodes[d].name, version: nodes[d].version,
      flux: flux.get(d), share: total ? flux.get(d) / (organism.wmax ? total / organism.wmax : 1) : 0,
      tube: tube.get(d), coverage: coverage(new Set(set)), items,
    };
  }

  const finalCov = acts.length ? acts.at(-1).coverage : coverage(new Set());
  const greedyCov = coverage(greedy);
  const unfixed = food.filter((f) => !f.fixed);
  // The act at which each food source closes (null: the ritual never closes it).
  const closedAt = food.map((f) => {
    if (!f.fixed) return null;
    const k = carriers.get(f.node).reduce((mx, c) => Math.max(mx, chosen.indexOf(c) === -1 ? Infinity : chosen.indexOf(c)), -1);
    return Number.isFinite(k) && k >= 0 ? k : null;
  });

  return {
    total, fixable: total ? fixable / total : 1, acts, coverage: finalCov,
    state: stateFor(food.length ? finalCov : 1),
    secondOpinion: greedyCov > finalCov + 1e-9
      ? { coverage: greedyCov, roots: [...greedy].map((d) => nodes[d].name) } : null,
    unfixed, closedAt, overrides: overridesFor(nodes, acts, direct),
    unreached: food.filter((f) => !carriers.get(f.node).length),
  };
}

// The script as written to package.json: root bumps, scoped overrides, and, in a
// workspace project, bumps for each member manifest.
export function scriptOf(ritual) {
  const { bumps, overrides, workspaces } = ritual.overrides;
  return { dependencies: bumps, overrides, ...(Object.keys(workspaces ?? {}).length ? { workspaces } : {}) };
}

// The overridden packages, by bare name: what `npm update` must re-resolve.
export function refreshList(ritual) {
  const out = new Set();
  const walk = (o) => { for (const [k, v] of Object.entries(o)) typeof v === 'string' ? out.add(k) : walk(v); };
  walk(ritual.overrides.overrides);
  return [...out].sort();
}

// The thickest-tube path from a direct dependency down to the vulnerable package.
function pathTo(edges, organism, from, to, anc) {
  const kids = new Map();
  edges.forEach(([a, b], i) => { if (anc[a] && anc[b]) (kids.get(a) ?? kids.set(a, []).get(a)).push([b, i]); });
  const path = [from];
  let cur = from;
  for (let guard = 0; cur !== to && guard < 64; guard++) {
    const next = (kids.get(cur) ?? []).sort((x, y) => organism.D[y[1]] - organism.D[x[1]])[0];
    if (!next) break;
    cur = next[0]; path.push(cur);
  }
  return path;
}

// npm `overrides`, scoped under each act's direct dependency, so a fix lands only
// in the subtree the act claims. A vulnerable direct dependency is bumped in
// `dependencies` instead — npm rejects overriding a direct dep (EOVERRIDE). In a
// workspace project the bump goes to each member manifest that declares it.
//
// One act can carry the same package on two major lines (nanoid 3 under one
// parent, nanoid 4 under another). A single rule would drag both to the highest
// fix, so those copies are each scoped under their own parent instead.
//
// npm matches an override key by name anywhere in the tree, not only at the top.
// When the terrain holds another package of the same name (an act "mermaid" and
// a nested mermaid@11 under another act), a bare key would also capture that
// copy and replace the rules it inherited, so the key is pinned: "mermaid@12.2.0".
function overridesFor(nodes, acts, direct) {
  const overrides = {}, bumps = {}, workspaces = {}, majors = [];
  const major = (v) => v.split('.')[0];
  const count = new Map();
  for (const n of nodes.slice(1)) count.set(n.name, (count.get(n.name) ?? 0) + 1);
  const key = (id) => (count.get(nodes[id].name) > 1 && nodes[id].version ? `${nodes[id].name}@${nodes[id].version}` : nodes[id].name);
  for (const act of acts) {
    const items = act.items.filter((it) => it.fixed && nodes[it.node].ecosystem === 'npm');
    const lines = new Map();
    for (const it of items) (lines.get(it.name) ?? lines.set(it.name, new Set()).get(it.name)).add(major(it.version));
    for (const it of items) {
      if (it.node === act.root) {
        for (const file of nodes[it.node].manifests ?? ['package.json']) {
          if (file === 'package.json') bumps[it.name] = `^${it.fixed}`;
          else (workspaces[file.slice(0, -'/package.json'.length)] ??= {})[it.name] = `^${it.fixed}`;
        }
        continue;
      }
      if (direct.has(it.node)) continue;
      let scope = (overrides[key(act.root)] ??= {});
      const parent = it.path.length > 2 ? key(it.path.at(-2)) : null;
      if (lines.get(it.name).size > 1 && parent) scope = (scope[parent] ??= {});
      const prev = typeof scope[it.name] === 'string' ? scope[it.name].slice(1) : null;
      if (!prev || compare(it.fixed, prev) > 0) scope[it.name] = `^${it.fixed}`;
      if (major(it.fixed) !== major(it.version)) majors.push(`${it.name} ${it.version} → ${it.fixed}`);
    }
  }
  return { overrides, bumps, workspaces, majors: [...new Set(majors)] };
}
