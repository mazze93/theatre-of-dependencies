// Builds the standalone stage: one HTML file, data embedded, no network needed
// except the optional web fonts. Every animated frame is a recorded solver step.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scriptOf } from './ritual.mjs';

const TEMPLATE = fileURLToPath(new URL('../stage/template.html', import.meta.url));

export function stageData(terrain, food, organism, ritual, meta) {
  const m = terrain.edges.length;
  const frames = Buffer.alloc(organism.frames.length * m);
  organism.frames.forEach((f, i) => frames.set(f, i * m));

  // A tube seals when every food source that flows through it has closed.
  const closedAt = ritual.closedAt;
  const sealedAt = new Array(m).fill(-1);   // -1: never carried food
  organism.routes.forEach((r) => {
    const c = closedAt[food.findIndex((f) => f.node === r.node)];
    for (const e of r.edgeSet) {
      if (sealedAt[e] === null) continue;
      sealedAt[e] = c === null ? null : Math.max(sealedAt[e], c);
    }
  });

  return {
    meta, project: terrain.project,
    nodes: terrain.nodes.map((n) => [n.name, n.version, n.dev ? 1 : 0, organism.live[n.id] ? 1 : 0]),
    edges: terrain.edges,
    frames: frames.toString('base64'), frameCount: organism.frames.length,
    steps: organism.steps, converged: organism.converged, gamma: organism.params.gamma,
    food: food.map((f, i) => ({
      node: f.node, w: f.w, fixed: f.fixed, closedAt: closedAt[i],
      label: f.advisories[0].label, count: f.advisories.length,
      top: { id: f.advisories[0].id, summary: f.advisories[0].summary },
    })),
    acts: ritual.acts.map((a) => ({
      root: a.root, name: a.name, version: a.version, coverage: a.coverage,
      items: a.items.map((it) => ({ name: it.name, version: it.version, fixed: it.fixed, label: it.advisories[0].label, count: it.advisories.length, shared: it.sharedWith })),
    })),
    sealedAt,
    state: ritual.state, coverage: ritual.coverage, fixable: ritual.fixable,
    unfixed: ritual.unfixed.map((f) => ({ name: f.name, version: f.version, id: (f.advisories.find((a) => !a.fixed) ?? f.advisories[0]).id })),
    script: scriptOf(ritual),
    majors: ritual.overrides.majors,
  };
}

// JSON inside <script type="application/json">: escape everything that could end
// the element or open a comment. Package names are attacker-controlled input.
const safeJSON = (v) => JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);

export function renderStage(data) {
  return readFileSync(TEMPLATE, 'utf8').replace('"__STAGE_DATA__"', () => safeJSON(data));
}
