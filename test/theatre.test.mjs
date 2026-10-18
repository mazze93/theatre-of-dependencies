import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { cvss3Score, severityOf } from '../src/severity.mjs';
import { compare, fixedFor } from '../src/semver.mjs';
import { fromNpmLock, fromCycloneDX } from '../src/graph.mjs';
import { grow } from '../src/physarum.mjs';
import { stageRitual } from '../src/ritual.mjs';
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
