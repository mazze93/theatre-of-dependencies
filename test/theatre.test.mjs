import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { cvss3Score, severityOf } from '../src/severity.mjs';
import { compare, fixedFor } from '../src/semver.mjs';
import { fromNpmLock, fromCycloneDX } from '../src/graph.mjs';
import { grow } from '../src/physarum.mjs';
import { stageRitual, refreshList } from '../src/ritual.mjs';
import { stageData, renderStage } from '../src/stage.mjs';

const BIN = fileURLToPath(new URL('../bin/theatre.mjs', import.meta.url));

test('CVSS 3.x base scores match the FIRST calculator', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'), 7.2);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3Score('CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('CVSS:4.0/AV:N'), null);
  assert.deepEqual(severityOf({ database_specific: { severity: 'MODERATE' } }), { score: 5, label: 'MODERATE', source: 'label' });
});

test('semver ordering and fix-line selection', () => {
  assert.equal(compare('1.2.10', '1.2.9'), 1);
  assert.equal(compare('2.0.0-rc.1', '2.0.0'), -1);
  assert.equal(compare('2.0.0-rc.2', '2.0.0-rc.10'), -1);
  const qs = [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '6.2.4' }, { introduced: '6.3.0' }, { fixed: '6.3.3' }, { introduced: '6.7.0' }, { fixed: '6.7.3' }] }];
  assert.equal(fixedFor('6.7.0', qs), '6.7.3');
  assert.equal(fixedFor('6.3.1', qs), '6.3.3');
  assert.equal(fixedFor('6.7.3', qs), null);
  assert.equal(fixedFor('1.0.0', [{ type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '1.0.0' }] }]), null);
});

test('npm v3 lockfile: nested node_modules resolve like Node does', () => {
  const lock = { lockfileVersion: 3, packages: {
    '': { name: 'app', dependencies: { a: '1', b: '1' }, devDependencies: { t: '1' } },
    'node_modules/a': { version: '1.0.0', dependencies: { c: '1' } },
    'node_modules/b': { version: '1.0.0', dependencies: { c: '2' } },
    'node_modules/b/node_modules/c': { version: '2.0.0' },
    'node_modules/c': { version: '1.0.0' },
    'node_modules/t': { version: '1.0.0', dev: true },
  } };
  const g = fromNpmLock(lock);
  const id = (path) => g.nodes.findIndex((n) => `${n.name}@${n.version}` === path);
  const has = (a, b) => g.edges.some(([x, y]) => x === id(a) && y === id(b));
  assert.ok(has('a@1.0.0', 'c@1.0.0'));
  assert.ok(has('b@1.0.0', 'c@2.0.0'));
  assert.ok(!has('b@1.0.0', 'c@1.0.0'));
  assert.ok(g.edges.some(([x, y]) => x === 0 && y === id('t@1.0.0')));
  assert.equal(g.nodes[id('t@1.0.0')].dev, true);
});

test('npm workspaces: members fold into the project, their deps are its entrances', () => {
  const lock = { lockfileVersion: 3, packages: {
    '': { name: 'mono', workspaces: ['app', 'lib'], devDependencies: { fonts: '1' } },
    app: { name: '@m/app', version: '0.1.0', dependencies: { '@m/lib': '0.1.0', ui: '1' }, devDependencies: { bundler: '1' } },
    lib: { name: '@m/lib', version: '0.1.0', dependencies: { tiny: '1' } },
    'node_modules/@m/app': { resolved: 'app', link: true },
    'node_modules/@m/lib': { resolved: 'lib', link: true },
    'node_modules/ui': { version: '2.0.0', dependencies: { tiny: '2' } },
    'node_modules/ui/node_modules/tiny': { version: '2.0.0' },
    'node_modules/tiny': { version: '1.0.0' },
    'node_modules/bundler': { version: '1.0.0', dev: true },
    'node_modules/fonts': { version: '1.0.0', dev: true },
  } };
  const g = fromNpmLock(lock);
  const id = (nv) => g.nodes.findIndex((n) => `${n.name}@${n.version}` === nv);
  const fromRoot = (nv) => g.edges.some(([x, y]) => x === 0 && y === id(nv));
  // Members are the project itself, not packages on the terrain.
  assert.equal(id('@m/app@0.1.0'), -1);
  assert.equal(id('@m/lib@0.1.0'), -1);
  for (const nv of ['ui@2.0.0', 'bundler@1.0.0', 'tiny@1.0.0', 'fonts@1.0.0']) assert.ok(fromRoot(nv), nv);
  assert.ok(g.edges.some(([x, y]) => x === id('ui@2.0.0') && y === id('tiny@2.0.0')));
  assert.ok(!g.edges.some(([, y]) => y === 0), 'nothing points back at the project');
  // A bump must land in the manifest that declares the dependency.
  assert.deepEqual(g.nodes[id('ui@2.0.0')].manifests, ['app/package.json']);
  assert.deepEqual(g.nodes[id('tiny@1.0.0')].manifests, ['lib/package.json']);
  assert.deepEqual(g.nodes[id('fonts@1.0.0')].manifests, ['package.json']);
});

test('a vulnerable direct dependency of a workspace is bumped in that workspace', () => {
  const t = diamond();
  t.nodes[3].manifests = ['app/package.json'];
  const food = [{ node: 3, name: 'n3', version: '1.0.0', w: 1, fixed: '1.0.4',
    advisories: [{ id: 'GHSA-z', label: 'HIGH', score: 7.5, fixed: '1.0.4', summary: '' }] }];
  const r = stageRitual(t, food, grow(t, food));
  assert.equal(r.coverage, 1);
  assert.deepEqual(r.overrides.bumps, {});
  assert.deepEqual(r.overrides.workspaces, { app: { n3: '^1.0.4' } });
});

test('one act, one package on two major lines: each copy is scoped under its own parent', () => {
  // project(0) → E(1);  E → v3(2);  E → M(3) → v4(4)   (v3 and v4 are the same package)
  const t = { project: 'p', edges: [[0, 1], [1, 2], [1, 3], [3, 4]], nodes: [
    { id: 0, name: 'p', version: '', ecosystem: 'npm' }, { id: 1, name: 'E', version: '1.0.0', ecosystem: 'npm' },
    { id: 2, name: 'nano', version: '3.3.3', ecosystem: 'npm' }, { id: 3, name: 'M', version: '1.0.0', ecosystem: 'npm' },
    { id: 4, name: 'nano', version: '4.0.2', ecosystem: 'npm' }] };
  const adv = (fixed) => [{ id: 'GHSA-n', label: 'HIGH', score: 7.5, fixed, summary: '' }];
  const food = [{ node: 2, name: 'nano', version: '3.3.3', w: 1, fixed: '3.3.18', advisories: adv('3.3.18') },
    { node: 4, name: 'nano', version: '4.0.2', w: 1, fixed: '5.1.16', advisories: adv('5.1.16') }];
  const r = stageRitual(t, food, grow(t, food), { backbone: 0 });
  // A single flat rule would have dragged nano 3.3.3 to ^5.1.16.
  assert.deepEqual(r.overrides.overrides, { E: { nano: '^3.3.18', M: { nano: '^5.1.16' } } });
});

test('an act whose name recurs deeper in the tree gets a version-pinned key', () => {
  // project → A(1) → M@11(3) → k(4);  project → M@12(2) → k2(5)
  // npm matches a bare "M" key at every depth, so M@11 under A would lose A's rules.
  const n = (id, name, version) => ({ id, name, version, ecosystem: 'npm' });
  const t = { project: 'p', edges: [[0, 1], [0, 2], [1, 3], [3, 4], [2, 5]],
    nodes: [n(0, 'p', ''), n(1, 'A', '1.0.0'), n(2, 'M', '12.0.0'), n(3, 'M', '11.0.0'), n(4, 'k', '0.16.0'), n(5, 'l', '4.0.0')] };
  const adv = (fixed) => [{ id: 'GHSA-k', label: 'HIGH', score: 7.5, fixed, summary: '' }];
  const food = [{ node: 4, name: 'k', version: '0.16.0', w: 1, fixed: '0.18.2', advisories: adv('0.18.2') },
    { node: 5, name: 'l', version: '4.0.0', w: 1, fixed: '4.1.0', advisories: adv('4.1.0') }];
  const r = stageRitual(t, food, grow(t, food), { backbone: 0 });
  assert.deepEqual(r.overrides.overrides, { A: { k: '^0.18.2' }, 'M@12.0.0': { l: '^4.1.0' } });
  assert.deepEqual(refreshList(r), ['k', 'l']);
});

test('CycloneDX: purl ecosystems, dependency tree, orphans hang off the project', () => {
  const g = fromCycloneDX({ bomFormat: 'CycloneDX', metadata: { component: { 'bom-ref': 'root', name: 'svc' } },
    components: [{ 'bom-ref': 'r', name: 'requests', version: '2.19.0', purl: 'pkg:pypi/requests@2.19.0' },
      { 'bom-ref': 'u', name: 'urllib3', version: '1.23', purl: 'pkg:pypi/urllib3@1.23' },
      { 'bom-ref': 'x', name: 'lonely', version: '1.0', purl: 'pkg:cargo/lonely@1.0' }],
    dependencies: [{ ref: 'root', dependsOn: ['r'] }, { ref: 'r', dependsOn: ['u'] }] });
  assert.equal(g.nodes[1].ecosystem, 'PyPI');
  assert.equal(g.nodes[3].ecosystem, 'crates.io');
  assert.deepEqual(g.edges, [[0, 1], [1, 2], [0, 3]]);
});

// project(0) → A(1), B(2), C(3);  A → V(4), B → V(4);  C → leaf(5)
const diamond = () => ({ project: 'p', nodes: [0, 1, 2, 3, 4, 5].map((id) => ({ id, name: `n${id}`, version: '1.0.0', ecosystem: 'npm' })),
  edges: [[0, 1], [0, 2], [0, 3], [1, 4], [2, 4], [3, 5]] });

test('the organism: rival routes compete, unfed tubes starve', () => {
  const t = diamond();
  const org = grow(t, [{ node: 4, w: 1 }]);
  const D = (a, b) => org.D[t.edges.findIndex(([x, y]) => x === a && y === b)];
  const [win, lose] = D(0, 1) > D(0, 2) ? [D(0, 1), D(0, 2)] : [D(0, 2), D(0, 1)];
  assert.ok(win > 0.2, `winner should hold a tube, got ${win}`);
  assert.ok(lose < win / 5, `loser should starve: ${lose} vs ${win}`);
  assert.ok(D(0, 3) < 1e-3 && D(3, 5) < 1e-3, 'tubes that carry no food decay');
  assert.ok(org.frames.length > 10 && org.frames.every((f) => f.length === t.edges.length));
});

test('the ritual: coverage is the exact cut, not the organism\'s opinion', () => {
  const t = diamond();
  const food = [{ node: 4, name: 'n4', version: '1.0.0', w: 1, fixed: '1.0.1',
    advisories: [{ id: 'GHSA-x', label: 'HIGH', score: 7.5, fixed: '1.0.1', summary: '' }] }];
  const org = grow(t, food);
  const r = stageRitual(t, food, org, { maxActs: 1 });
  assert.equal(r.acts.length, 1);
  // V enters through A and B; one act cannot close it, whatever the organism chose.
  assert.equal(r.coverage, 0);
  assert.equal(r.acts[0].items[0].sharedWith.length, 1);
  assert.equal(r.state.key, 'open');
  const r2 = stageRitual(t, food, grow(t, food), { maxActs: 2, backbone: 0 });
  assert.equal(r2.coverage, 1);
  assert.equal(r2.closedAt[0], 1);
  // fixes are scoped under each act; a direct dependency is bumped, never overridden
  assert.deepEqual(Object.keys(r2.overrides.overrides).sort(), ['n1', 'n2']);
  assert.deepEqual(r2.overrides.overrides.n1, { n4: '^1.0.1' });
});

test('a vulnerable direct dependency is closed by bumping it alone', () => {
  const t = diamond();
  const food = [{ node: 3, name: 'n3', version: '1.0.0', w: 1, fixed: '2.0.0',
    advisories: [{ id: 'GHSA-y', label: 'CRITICAL', score: 9.8, fixed: '2.0.0', summary: '' }] }];
  const r = stageRitual(t, food, grow(t, food));
  assert.equal(r.coverage, 1);
  assert.equal(r.state.key, 'closed');
  assert.deepEqual(r.overrides.bumps, { n3: '^2.0.0' });
});

test('the stage escapes attacker-controlled package names', () => {
  const t = diamond();
  t.nodes[4].name = '</script><img src=x onerror=alert(1)>';
  const food = [{ node: 4, name: t.nodes[4].name, version: '1.0.0', w: 1, fixed: null,
    advisories: [{ id: 'GHSA-z', label: 'LOW', score: 2, fixed: null, summary: '<!--' }] }];
  const org = grow(t, food);
  const html = renderStage(stageData(t, food, org, stageRitual(t, food, org), { file: 'x', date: 'd', version: 'v' }));
  const data = html.slice(html.indexOf('id="stage-data">'), html.indexOf('</script>', html.indexOf('id="stage-data">')));
  assert.ok(!data.includes('<img') && !data.includes('<!--'));
  assert.ok(data.includes('\\u003c/script\\u003e'));
  // Behind Cloudflare, Rocket Loader defers inline scripts through a loader the
  // stage's own CSP blocks; the opt-out keeps the stage running when hosted.
  assert.match(html, /<script data-cfasync="false">\s*\(\(\) => \{/);
});

test('cli: demo runs offline, --json is machine-readable, --gate fails a thin ritual', () => {
  const out = execFileSync(process.execPath, [BIN, 'demo', '--json', '--no-open', '--out', '/dev/null'], { encoding: 'utf8' });
  const j = JSON.parse(out);
  assert.equal(j.project, 'vulnerable-shop');
  assert.ok(j.acts.length >= 1 && j.coverage > 0 && j.coverage <= 1);
  const gated = spawnSync(process.execPath, [BIN, 'demo', '--json', '--no-open', '--out', '/dev/null', '--gate', 'half']);
  assert.equal(gated.status, j.state === 'CLOSED' ? 0 : 3);
  const bad = spawnSync(process.execPath, [BIN, 'scan', '/nonexistent-path-for-test']);
  assert.equal(bad.status, 1);
});


test('npm workspaces fail explicitly instead of reporting disconnected coverage', () => {
  assert.throws(() => fromNpmLock({ lockfileVersion: 3, packages: {
    '': { name: 'root', workspaces: ['app'] },
    app: { name: '@demo/app', version: '1.0.0', dependencies: { vulnerable: '1' }, devDependencies: { tool: '1' } },
    'node_modules/@demo/app': { resolved: 'app', link: true },
    'node_modules/vulnerable': { version: '1.0.0' },
    'node_modules/tool': { version: '1.0.0', dev: true },
  } }), /workspaces\/local links are not supported/);
});

test('a vulnerable orphan receives no coverage credit and cannot close the gate', () => {
  const t = diamond(); t.edges = [[0, 1]];
  const food = [{ node: 4, name: 'n4', version: '1.0.0', w: 1, fixed: '1.0.1', advisories: [] }];
  const r = stageRitual(t, food, grow(t, food));
  assert.equal(r.acts.length, 0);
  assert.equal(r.coverage, 0);
  assert.equal(r.state.key, 'open');
  assert.equal(r.unreached.length, 1);
});
