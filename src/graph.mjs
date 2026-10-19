// Terrain loaders. Both produce the same shape:
//   { project, nodes: [{ id, name, version, ecosystem, purl, dev }], edges: [[parent, child]] }
// Node 0 is always the project itself — the organism's heart, where all flux drains.

import { readFileSync, statSync, existsSync } from 'node:fs';
import { join, basename } from 'node:path';

export function loadTerrain(path) {
  let file = path;
  if (statSync(path).isDirectory()) {
    for (const cand of ['package-lock.json', 'npm-shrinkwrap.json', 'bom.json', 'sbom.json']) {
      if (existsSync(join(path, cand))) { file = join(path, cand); break; }
    }
    if (file === path) throw new Error(`no package-lock.json or CycloneDX bom.json in ${path}`);
  }
  let doc;
  try { doc = JSON.parse(readFileSync(file, 'utf8')); }
  catch (e) { throw new Error(`${file} is not valid JSON: ${e.message}`); }
  if (doc.bomFormat === 'CycloneDX') return { file, ...fromCycloneDX(doc) };
  if (doc.packages && doc.lockfileVersion >= 2) return { file, ...fromNpmLock(doc) };
  if (doc.lockfileVersion === 1) throw new Error('lockfileVersion 1 is not supported — run `npm install --package-lock-only` with npm ≥7 to upgrade it');
  throw new Error(`${basename(file)}: not an npm v2/v3 lockfile or a CycloneDX JSON SBOM`);
}

// npm v2/v3: keys are install paths ("node_modules/a/node_modules/b"). A dependency
// named N declared at path P resolves the way Node does: P/node_modules/N, then
// each ancestor's node_modules/N, up to the top level.
export function fromNpmLock(lock) {
  const pkgs = lock.packages;
  const root = pkgs[''] ?? {};
  // Workspace ownership and upgrade targets are not represented by this graph yet.
  // Refuse instead of silently disconnecting the app and claiming coverage.
  if (root.workspaces || Object.values(pkgs).some(meta => meta.link)) {
    throw new Error('npm workspaces/local links are not supported yet; coverage and upgrade ownership cannot be established');
  }
  const nodes = [{ id: 0, name: root.name ?? lock.name ?? 'project', version: root.version ?? '', ecosystem: 'npm', purl: null, dev: false }];
  const index = new Map([['', 0]]);
  for (const [p, meta] of Object.entries(pkgs)) {
    if (p === '' || meta.link) continue;
    const name = meta.name ?? p.slice(p.lastIndexOf('node_modules/') + 13);
    index.set(p, nodes.length);
    nodes.push({ id: nodes.length, name, version: meta.version ?? '', ecosystem: 'npm',
      purl: `pkg:npm/${name.replace('@', '%40')}@${meta.version}`, dev: !!meta.dev });
  }
  const links = new Map(Object.entries(pkgs).filter(([, m]) => m.link).map(([p, m]) => [p, m.resolved]));

  const resolve = (from, dep) => {
    let base = from;
    for (;;) {
      let cand = (base ? `${base}/` : '') + `node_modules/${dep}`;
      if (links.has(cand)) cand = links.get(cand);
      if (index.has(cand)) return index.get(cand);
      if (!base) return null;
      const cut = base.lastIndexOf('/node_modules/');
      base = cut === -1 ? '' : base.slice(0, cut);
    }
  };

  const edges = [], seen = new Set();
  for (const [p, meta] of Object.entries(pkgs)) {
    if (meta.link || !index.has(p)) continue;
    const from = index.get(p);
    const deps = { ...meta.dependencies, ...meta.optionalDependencies,
      ...(p === '' ? meta.devDependencies : {}) };
    for (const dep of Object.keys(deps)) {
      const to = resolve(p, dep);
      if (to == null || to === from) continue;
      const k = `${from}>${to}`;
      if (!seen.has(k)) { seen.add(k); edges.push([from, to]); }
    }
  }
  return { project: nodes[0].name, nodes, edges };
}

const PURL_ECO = { npm: 'npm', pypi: 'PyPI', golang: 'Go', maven: 'Maven', cargo: 'crates.io',
  gem: 'RubyGems', nuget: 'NuGet', composer: 'Packagist', hex: 'Hex', pub: 'Pub' };

// CycloneDX 1.4+: components[] keyed by bom-ref, dependencies[] {ref, dependsOn}.
export function fromCycloneDX(bom) {
  const meta = bom.metadata?.component;
  const nodes = [{ id: 0, name: meta?.name ?? 'project', version: meta?.version ?? '', ecosystem: null, purl: meta?.purl ?? null, dev: false }];
  const index = new Map();
  if (meta?.['bom-ref']) index.set(meta['bom-ref'], 0);
  for (const c of bom.components ?? []) {
    const ref = c['bom-ref'] ?? c.purl ?? `${c.name}@${c.version}`;
    const type = c.purl?.match(/^pkg:([^/]+)\//)?.[1];
    index.set(ref, nodes.length);
    nodes.push({ id: nodes.length, name: c.group ? `${c.group}/${c.name}` : c.name, version: c.version ?? '',
      ecosystem: PURL_ECO[type] ?? type ?? null, purl: c.purl ?? null, dev: c.scope === 'excluded' });
  }
  const edges = [], seen = new Set(), hasParent = new Set();
  for (const d of bom.dependencies ?? []) {
    const from = index.get(d.ref);
    if (from == null) continue;
    for (const r of d.dependsOn ?? []) {
      const to = index.get(r);
      if (to == null || to === from || seen.has(`${from}>${to}`)) continue;
      seen.add(`${from}>${to}`); edges.push([from, to]); hasParent.add(to);
    }
  }
  // An SBOM without a dependency tree is still terrain: hang orphans off the project.
  for (let i = 1; i < nodes.length; i++) if (!hasParent.has(i)) edges.push([0, i]);
  return { project: nodes[0].name, nodes, edges };
}
