// The organism. A multi-commodity form of the Tero et al. (Science 2010) adaptive
// network: each vulnerable package is a food source that injects current equal to
// its severity weight; the project is the sink. Each tube (dependency edge) e has
// conductivity D_e. Per step:
//
//   1. For every food source v, solve Kirchhoff's laws on the subgraph of v's
//      ancestors (every path the vulnerability can travel to reach the project):
//      Σ_j (D_ij / L_ij)(p_i − p_j) = b_i,  b_v = w_v, p_project = 0.
//   2. Total flux on a tube: Q_e = Σ_v |Q_e^v|.
//   3. Adapt: D_e ← D_e + dt·( f(Q_e) − D_e ),  f(Q) = Q^γ / (1 + Q^γ).
//
// γ > 1 makes parallel routes compete: the one that carries slightly more grows,
// the other starves, and the network collapses onto a minimal backbone. Tubes that
// carry no vulnerability at all receive f = 0 and decay — the terrain goes dark and
// only the veins that lead from vulnerable code to your project remain.
//
// Restricting each commodity to the ancestor subgraph matters: dependency edges are
// directed, and an unrestricted resistor network would let current leak "sideways"
// into packages that cannot actually deliver that vulnerability to the project.

export const DEFAULTS = { gamma: 1.8, dt: 0.06, steps: 480, frameEvery: 3, tol: 1e-4, minSteps: 120, Dmin: 1e-6 };

// Deterministic ±2% length jitter so perfectly symmetric graphs still break ties.
function jitter(a, b) {
  let x = (Math.imul(a + 1, 0x9e3779b1) ^ Math.imul(b + 7, 0x85ebca77)) >>> 0;
  x ^= x >>> 15; x = Math.imul(x, 0x2c1b3c6d) >>> 0; x ^= x >>> 12;
  return 1 + ((x % 4001) / 4000 - 0.5) * 0.04;
}

export function reachableFrom(n, edges, src = 0) {
  const kids = Array.from({ length: n }, () => []);
  for (const [a, b] of edges) kids[a].push(b);
  const seen = new Uint8Array(n); seen[src] = 1;
  const stack = [src];
  while (stack.length) for (const c of kids[stack.pop()]) if (!seen[c]) { seen[c] = 1; stack.push(c); }
  return seen;
}

export function ancestorsOf(n, edges, v, live) {
  const parents = Array.from({ length: n }, () => []);
  for (const [a, b] of edges) parents[b].push(a);
  const seen = new Uint8Array(n); seen[v] = 1;
  const stack = [v];
  while (stack.length) for (const p of parents[stack.pop()]) if (!seen[p] && live[p]) { seen[p] = 1; stack.push(p); }
  return seen;
}

// One commodity: local index of its node set, local edge list, warm-start potentials.
function commodity(n, edges, food, live, edgeIndex) {
  const inSet = ancestorsOf(n, edges, food.node, live);
  const g2l = new Map(); const l2g = [];
  for (let i = 0; i < n; i++) if (inSet[i]) { g2l.set(i, l2g.length); l2g.push(i); }
  const local = [];
  for (const [a, b] of edges) if (inSet[a] && inSet[b]) local.push([g2l.get(a), g2l.get(b), edgeIndex.get(`${a}>${b}`)]);
  return { food, n: l2g.length, l2g, sink: g2l.get(0), src: g2l.get(food.node), local, p: new Float64Array(l2g.length) };
}

// Preconditioned conjugate gradient on the grounded weighted Laplacian.
function solve(c, cond) {
  const { n, sink, src, local, p } = c;
  const diag = new Float64Array(n);
  for (const [a, b, e] of local) { diag[a] += cond[e]; diag[b] += cond[e]; }
  const A = (x, out) => {
    out.fill(0);
    for (const [a, b, e] of local) { const f = cond[e] * (x[a] - x[b]); out[a] += f; out[b] -= f; }
    out[sink] = 0;
  };
  const bvec = new Float64Array(n); bvec[src] = c.food.w;
  p[sink] = 0;
  const r = new Float64Array(n), z = new Float64Array(n), d = new Float64Array(n), Ad = new Float64Array(n);
  A(p, Ad);
  for (let i = 0; i < n; i++) r[i] = i === sink ? 0 : bvec[i] - Ad[i];
  for (let i = 0; i < n; i++) { z[i] = i === sink ? 0 : r[i] / (diag[i] || 1); d[i] = z[i]; }
  let rz = 0; for (let i = 0; i < n; i++) rz += r[i] * z[i];
  const bnorm = Math.abs(c.food.w) || 1;
  for (let it = 0; it < 4 * n + 50; it++) {
    let rn = 0; for (let i = 0; i < n; i++) rn += r[i] * r[i];
    if (Math.sqrt(rn) < 1e-10 * bnorm) break;
    A(d, Ad);
    let dAd = 0; for (let i = 0; i < n; i++) dAd += d[i] * Ad[i];
    if (dAd <= 0) break;
    const alpha = rz / dAd;
    for (let i = 0; i < n; i++) { p[i] += alpha * d[i]; r[i] -= alpha * Ad[i]; }
    let rz2 = 0;
    for (let i = 0; i < n; i++) { z[i] = i === sink ? 0 : r[i] / (diag[i] || 1); rz2 += r[i] * z[i]; }
    const beta = rz2 / rz; rz = rz2;
    for (let i = 0; i < n; i++) d[i] = z[i] + beta * d[i];
  }
}

/**
 * @param terrain {nodes, edges}
 * @param food [{node, w}] — w is severity weight
 * @returns {D, Q, frames, steps, converged, commodities}
 */
export function grow(terrain, food, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const n = terrain.nodes.length, edges = terrain.edges, m = edges.length;
  const live = reachableFrom(n, edges, 0);
  const edgeIndex = new Map(edges.map(([a, b], i) => [`${a}>${b}`, i]));
  const L = Float64Array.from(edges, ([a, b]) => jitter(a, b));
  const D = new Float64Array(m).fill(1);
  const cond = new Float64Array(m);
  const Q = new Float64Array(m);

  // Normalise food so the heaviest source injects 1: the sigmoid f then reads
  // "one critical advisory" as half-saturation, and shared trunks saturate.
  const wmax = Math.max(1e-9, ...food.map((f) => f.w));
  const comms = food.filter((f) => live[f.node] && f.node !== 0)
    .map((f) => commodity(n, edges, { ...f, w: f.w / wmax }, live, edgeIndex));

  const frames = [];
  const snap = () => frames.push(Uint8Array.from(D, (x) => Math.max(0, Math.min(255, Math.round(Math.sqrt(x) * 255)))));
  snap();

  let step = 0, converged = null;
  for (; step < o.steps; step++) {
    for (let e = 0; e < m; e++) cond[e] = Math.max(D[e], o.Dmin) / L[e];
    Q.fill(0);
    for (const c of comms) {
      solve(c, cond);
      for (const [a, b, e] of c.local) Q[e] += Math.abs(cond[e] * (c.p[a] - c.p[b]));
    }
    let delta = 0;
    for (let e = 0; e < m; e++) {
      const qg = Math.pow(Q[e], o.gamma);
      const next = D[e] + o.dt * (qg / (1 + qg) - D[e]);
      delta = Math.max(delta, Math.abs(next - D[e]));
      D[e] = next;
    }
    if ((step + 1) % o.frameEvery === 0) snap();
    if (step >= o.minSteps && delta < o.tol) { converged = step + 1; break; }
  }
  if (frames.length < 2 || (step + 1) % o.frameEvery !== 0) snap();

  // Final per-commodity flux so the ritual can say which entrance each advisory took.
  for (let e = 0; e < m; e++) cond[e] = Math.max(D[e], o.Dmin) / L[e];
  Q.fill(0);
  const routes = [];
  for (const c of comms) {
    solve(c, cond);
    const viaRoot = new Map();
    for (const [a, b, e] of c.local) {
      const q = Math.abs(cond[e] * (c.p[a] - c.p[b]));
      Q[e] += q;
      const [ga, gb] = [c.l2g[a], c.l2g[b]];
      if (ga === 0) viaRoot.set(gb, (viaRoot.get(gb) ?? 0) + q);
    }
    routes.push({ node: c.food.node, edgeSet: c.local.map((x) => x[2]), carriers: [...viaRoot.keys()].sort((x, y) => viaRoot.get(y) - viaRoot.get(x)), viaRoot });
  }

  return { D, Q, frames, steps: Math.min(step + 1, o.steps), converged, routes, live, params: o, wmax };
}
