#!/usr/bin/env node
// theatre — a slime mold reads your dependency graph and stages an upgrade ritual.

import { parseArgs } from 'node:util';
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { resolve, relative, join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

import { loadTerrain } from '../src/graph.mjs';
import { OSV } from '../src/osv.mjs';
import { gatherFood } from '../src/feed.mjs';
import { grow } from '../src/physarum.mjs';
import { stageRitual, STATES } from '../src/ritual.mjs';
import { performGrowth, playbill, scriptBlock, colorOn } from '../src/render-term.mjs';
import { stageData, renderStage } from '../src/stage.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const VERSION = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;

const HELP = `
  theatre — a slime mold reads your dependency graph and stages an upgrade ritual

  usage
    theatre scan  [path]     read a lockfile or SBOM, grow the organism, print the playbill
    theatre stage [path]     the same, then write and open the animated stage (HTML)
    theatre demo             run both on the bundled vulnerable-shop fixture, offline

  path      a directory, package-lock.json (v2/v3), or CycloneDX JSON SBOM   (default: .)

  options
    --prod              ignore devDependencies
    --max-acts <n>      longest ritual to stage                               (default 7)
    --gate <state>      exit 3 if the ritual leaves the project at or below
                        this state: open | half                               (for CI)
    --json              machine-readable result on stdout, nothing else
    --write <file>      also write the script (bumps + overrides) as JSON
    --out <file>        stage file                                            (default theatre-stage.html)
    --no-open           write the stage but don't open it
    --offline           use the advisory cache only; never touch the network
    --cache <dir>       advisory cache                         (default ~/.cache/theatre-of-dependencies)
    --no-anim           skip the growth sequence
    -v, --version       print the version
    -h, --help          this

  exit codes  0 ok · 1 error · 3 gate failed
`;

function fail(msg) { process.stderr.write(`theatre: ${msg}\n`); process.exit(1); }

let args;
try {
  args = parseArgs({
    allowPositionals: true,
    options: {
      prod: { type: 'boolean' }, 'max-acts': { type: 'string' }, gate: { type: 'string' },
      json: { type: 'boolean' }, write: { type: 'string' }, out: { type: 'string' },
      'no-open': { type: 'boolean' }, offline: { type: 'boolean' }, cache: { type: 'string' },
      'no-anim': { type: 'boolean' }, version: { type: 'boolean', short: 'v' }, help: { type: 'boolean', short: 'h' },
    },
  });
} catch (e) { fail(`${e.message}\n${HELP}`); }

const { values: o, positionals } = args;
if (o.version) { console.log(VERSION); process.exit(0); }
const [cmd = 'help', target] = positionals;
if (o.help || cmd === 'help' || !['scan', 'stage', 'demo'].includes(cmd)) {
  process.stdout.write(HELP);
  process.exit(o.help || cmd === 'help' ? 0 : 1);
}
if (o.gate && !['open', 'half'].includes(o.gate)) fail('--gate takes open or half');
const maxActs = o['max-acts'] ? Number.parseInt(o['max-acts'], 10) : 7;
if (!(maxActs >= 1 && maxActs <= 12)) fail('--max-acts must be 1–12');

const demo = cmd === 'demo';
// Fixture files are deliberately not named package*.json, so dependency scanners
// don't raise its intentionally vulnerable pins as alerts against this repo.
const path = resolve(demo ? join(ROOT, 'fixtures/vulnerable-shop/lockfile.fixture.json') : target ?? '.');
const cacheDir = o.cache ? resolve(o.cache) : demo ? join(ROOT, 'fixtures/vulnerable-shop/.osv-cache') : join(homedir(), '.cache/theatre-of-dependencies');
const quiet = !!o.json;
const log = (m) => { if (!quiet) process.stderr.write(`  ${colorOn ? '\x1b[2m' : ''}${m}${colorOn ? '\x1b[0m' : ''}\n`); };

try {
  const terrain = loadTerrain(path);
  const shown = relative(process.cwd(), terrain.file) || terrain.file;
  const osv = new OSV({ cacheDir, offline: o.offline || demo, log });
  const food = await gatherFood(terrain, osv, { prod: o.prod });
  if (osv.stats.missing) log(`${osv.stats.missing} lookups missing from the offline cache — results are incomplete`);
  const organism = grow(terrain, food);
  const ritual = stageRitual(terrain, food, organism, { maxActs });

  if (o.json) {
    process.stdout.write(JSON.stringify({
      version: VERSION, file: shown, project: terrain.project,
      terrain: { packages: terrain.nodes.length - 1, edges: terrain.edges.length },
      organism: { steps: organism.steps, converged: organism.converged, gamma: organism.params.gamma },
      state: ritual.state.label, coverage: ritual.coverage, closable: ritual.fixable,
      acts: ritual.acts.map((a) => ({ name: a.name, version: a.version, coverage: a.coverage,
        closes: a.items.map((it) => ({ name: it.name, version: it.version, fixed: it.fixed, alsoVia: it.sharedWith,
          advisories: it.advisories.map((x) => ({ id: x.id, aliases: x.aliases, label: x.label, score: x.score, fixed: x.fixed })) })) })),
      secondOpinion: ritual.secondOpinion,
      unfixed: ritual.unfixed.map((f) => ({ name: f.name, version: f.version, advisories: f.advisories.map((x) => x.id) })),
      script: { dependencies: ritual.overrides.bumps, overrides: ritual.overrides.overrides, majorJumps: ritual.overrides.majors },
    }, null, 2) + '\n');
  } else {
    if (!o['no-anim'] && food.length) await performGrowth(terrain, organism, ritual);
    process.stdout.write(playbill(terrain, food, organism, ritual, { file: shown }));
    process.stdout.write('\n' + scriptBlock(ritual));
  }

  if (o.write) {
    writeFileSync(resolve(o.write), JSON.stringify({ dependencies: ritual.overrides.bumps, overrides: ritual.overrides.overrides }, null, 2) + '\n');
    log(`script written to ${o.write}`);
  }

  if (cmd === 'stage' || demo) {
    const out = resolve(o.out ?? 'theatre-stage.html');
    mkdirSync(dirname(out), { recursive: true });
    const date = new Date().toISOString().slice(0, 10);
    writeFileSync(out, renderStage(stageData(terrain, food, organism, ritual, { file: shown, date, version: VERSION })));
    log(`stage written to ${relative(process.cwd(), out) || out}`);
    if (!o['no-open'] && !quiet) {
      const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'explorer' : 'xdg-open';
      spawn(opener, [out], { stdio: 'ignore', detached: true }).on('error', () => log(`open it yourself: ${out}`)).unref();
    }
  }

  if (o.gate) {
    const bar = STATES.findIndex((s) => s.key === o.gate);
    const at = STATES.findIndex((s) => s.key === ritual.state.key);
    if (at >= bar) { log(`gate: ${ritual.state.label} is at or below ${o.gate.toUpperCase()}`); process.exit(3); }
  }
} catch (e) {
  if (/fetch failed|ENOTFOUND|ECONNREFUSED|timeout/i.test(String(e.message) + String(e.cause))) fail(`could not reach OSV.dev (${e.cause?.code ?? e.message}). Re-run with --offline to use cached advisories.`);
  fail(e.message);
}
