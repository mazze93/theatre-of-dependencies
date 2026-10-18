// The terminal stage: a live growth sequence, then the playbill.

const env = process.env;
const out = process.stdout;
export const colorOn = !('NO_COLOR' in env) && (env.FORCE_COLOR ? env.FORCE_COLOR !== '0' : out.isTTY);
const truecolor = /truecolor|24bit/i.test(env.COLORTERM ?? '') || env.TERM_PROGRAM === 'iTerm.app' || env.TERM_PROGRAM === 'ghostty';

const PAL = {
  gold: [205, 162, 78, 178], bright: [230, 196, 120, 222], deep: [138, 111, 51, 136],
  teal: [92, 207, 207, 80], coral: [240, 113, 120, 210], paper: [236, 231, 218, 255],
  soft: [196, 189, 171, 250], muted: [163, 156, 132, 145], dim: [70, 66, 58, 239],
};
const paint = (name, s, bold = false) => {
  if (!colorOn) return s;
  const [r, g, b, c256] = PAL[name];
  const fg = truecolor ? `\x1b[38;2;${r};${g};${b}m` : `\x1b[38;5;${c256}m`;
  return `${bold ? '\x1b[1m' : ''}${fg}${s}\x1b[0m`;
};
const c = Object.fromEntries(Object.keys(PAL).map((k) => [k, (s, b) => paint(k, s, b)]));
const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');
const pad = (s, w) => s + ' '.repeat(Math.max(0, w - strip(s).length));
const ROMAN = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X', 'XI', 'XII'];
const WORDS = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve'];
const sevColor = { CRITICAL: 'coral', HIGH: 'bright', MODERATE: 'gold', LOW: 'muted', UNKNOWN: 'muted', NONE: 'muted' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A tube rendered by conductivity: dust → hairline → tube → vein.
function tubeGlyph(d) {
  if (d < 0.015) return ' ';
  if (d < 0.06) return '·';
  if (d < 0.18) return '─';
  if (d < 0.38) return '━';
  return '█';
}

function vein(d, width, phase, alive) {
  let s = '';
  for (let i = 0; i < width; i++) {
    const pulse = alive && d > 0.1 && ((i - phase) % 9 + 9) % 9 === 0;
    s += pulse ? '◆' : tubeGlyph(d);
  }
  const col = d >= 0.38 ? 'bright' : d >= 0.06 ? 'gold' : 'dim';
  return c[col](s);
}

// Plays the solver's recorded frames back over ~3.5 s. Every frame is a real step.
export async function performGrowth(terrain, organism, ritual, { rows = 12, duration = 3600 } = {}) {
  if (!out.isTTY || !colorOn) return;
  const rootEdges = terrain.edges.map((e, i) => [e, i]).filter(([[a]]) => a === 0);
  const fluxOf = new Map(rootEdges.map(([[, b], i]) => [b, organism.Q[i]]));
  const shown = rootEdges.sort((x, y) => (fluxOf.get(y[0][1]) ?? 0) - (fluxOf.get(x[0][1]) ?? 0)).slice(0, rows);
  const nameW = Math.min(26, Math.max(...shown.map(([[, b]]) => `${terrain.nodes[b].name}`.length)) + 1);
  const width = Math.max(16, Math.min(46, (out.columns ?? 80) - nameW - 26));
  const F = organism.frames, m = terrain.edges.length;
  const lines = shown.length + 4;
  out.write('\x1b[?25l');
  const restore = () => out.write('\x1b[?25h');
  process.once('exit', restore);
  const total = Math.max(60, Math.round(duration / 33));
  for (let t = 0; t <= total; t++) {
    const pos = (t / total) * (F.length - 1);
    const i0 = Math.floor(pos), i1 = Math.min(F.length - 1, i0 + 1), k = pos - i0;
    const D = (e) => { const a = F[i0][e] / 255, b = F[i1][e] / 255; const s = a + (b - a) * k; return s * s; };
    let alive = 0; for (let e = 0; e < m; e++) if (D(e) >= 0.05) alive++;
    const step = Math.round((pos / (F.length - 1)) * organism.steps);
    const buf = [];
    buf.push(`  ${c.gold('the organism grows', true)}  ${c.muted(`step ${String(step).padStart(3)} / ${organism.steps}`)}   ${c.soft(`${String(Math.round((alive / m) * 100)).padStart(3)}% of the terrain still alive`)}`);
    buf.push('');
    for (const [[, b], ei] of shown) {
      const d = D(ei), n = terrain.nodes[b];
      const label = d >= 0.06 ? c.paper(n.name) : c.muted(n.name);
      buf.push(`  ${pad(label, nameW)} ${c.deep('◁')}${vein(d, width, t, true)}${c.gold('●')} ${c.muted(d.toFixed(2))}`);
    }
    buf.push('');
    buf.push(`  ${c.muted('food ◆ enters on the left · flux drains to your project ● · unused tubes starve')}`);
    out.write((t ? `\x1b[${lines}F` : '') + buf.map((l) => `\x1b[2K${l}`).join('\n') + '\n');
    await sleep(33);
  }
  restore();
  out.write('\n');
}

export function playbill(terrain, food, organism, ritual, { file, max = 4 } = {}) {
  const L = [];
  const W = Math.min(74, (out.columns ?? 80) - 4);
  const rule = c.deep('═'.repeat(W));
  const counts = { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 };
  let advisories = 0;
  for (const f of food) for (const a of f.advisories) { counts[a.label] = (counts[a.label] ?? 0) + 1; advisories++; }
  const survivors = [...organism.D].filter((d) => d >= 0.05).length;
  const entrances = terrain.edges.filter(([a]) => a === 0).length;

  L.push('', `  ${rule}`);
  L.push(`     ${c.bright('T H E A T R E   O F   D E P E N D E N C I E S', true)}`);
  L.push(`     ${c.soft(`${terrain.project}`)} ${c.muted(`· a slime mold reads ${file ?? 'the terrain'}`)}`);
  L.push(`  ${rule}`, '');
  const row = (k, v) => L.push(`  ${pad(c.gold(k), 16)}${v}`);
  row('THE TERRAIN', c.paper(`${terrain.nodes.length - 1} packages · ${terrain.edges.length} tubes · ${entrances} entrances`));
  row('THE FOOD', food.length
    ? c.paper(`${food.length} vulnerable packages · ${advisories} advisories`)
    : c.paper('none — the organism has nothing to eat'));
  if (food.length) row('', ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].filter((s) => counts[s])
    .map((s) => `${c[sevColor[s]]('■')} ${c.soft(`${counts[s]} ${s.toLowerCase()}`)}`).join('  '));
  row('THE ORGANISM', c.paper(`${organism.converged ? `converged in ${organism.converged} steps` : `${organism.steps} steps (not converged)`} · γ ${organism.params.gamma} · ${survivors} of ${terrain.edges.length} tubes survive`));
  L.push('');

  if (!food.length) {
    L.push(`  ${c.gold('THE RITUAL')}  ${c.soft('none needed. OSV knows of no advisory affecting these versions.')}`);
  } else {
    const n = ritual.acts.length;
    L.push(`  ${c.gold('THE RITUAL', true)} ${c.muted('—')} ${c.paper(`${WORDS[n] ?? n} act${n === 1 ? '' : 's'} close ${Math.round(ritual.coverage * 100)}% of the vulnerable surface`)}`);
    L.push('');
    ritual.acts.forEach((act, i) => {
      const prev = i ? ritual.acts[i - 1].coverage : 0;
      const gain = act.coverage - prev;
      const bar = c.bright('━'.repeat(Math.max(1, Math.round(act.coverage * 18)))) + c.dim('─'.repeat(Math.max(0, 18 - Math.round(act.coverage * 18))));
      L.push(`  ${pad(c.gold(`ACT ${ROMAN[i] ?? i + 1}`, true), 10)}${pad(c.paper(`${act.name} ${c.muted(act.version)}`, true), 34)}${bar} ${c.bright(`${String(Math.round(act.coverage * 100)).padStart(3)}%`)} ${c.muted(gain > 0.0005 ? `+${Math.round(gain * 100)}` : ' ·')}`);
      const items = act.items.slice().sort((a, b) => b.w - a.w);
      for (const it of items.slice(0, max)) {
        const top = it.advisories[0];
        const arrow = it.fixed ? `${c.muted(it.version)} ${c.deep('→')} ${c.teal(it.fixed)}` : `${c.muted(it.version)} ${c.coral('✕ no fix')}`;
        const via = it.node === act.root ? c.muted('the act itself') : c.muted(`under ${it.path.slice(0, -1).map((p) => terrain.nodes[p].name).join(' › ')}`);
        L.push(`  ${' '.repeat(10)}${c.deep('├')} ${pad(c.soft(it.name), 22)} ${pad(arrow, 24)} ${pad(c[sevColor[top.label]](top.label), 9)} ${pad(c.muted(`${it.advisories.length}×`), 4)}  ${via}`);
        if (it.sharedWith.length) L.push(`  ${' '.repeat(10)}${c.deep('│')}   ${c.coral('↳')} ${c.muted(`also enters through ${it.sharedWith.join(', ')} — closed only when that act runs too`)}`);
      }
      if (items.length > max) L.push(`  ${' '.repeat(10)}${c.deep('└')} ${c.muted(`+ ${items.length - max} more in this act`)}`);
      L.push('');
    });
    if (ritual.secondOpinion) {
      L.push(`  ${c.teal('SECOND OPINION')}  ${c.soft(`an exact greedy cut over the same budget closes ${Math.round(ritual.secondOpinion.coverage * 100)}%: ${ritual.secondOpinion.roots.join(', ')}`)}`, '');
    }
    if (ritual.unfixed.length) {
      L.push(`  ${c.coral('THE BREAK', true)} ${c.muted('— kept on the record, not hidden')}`);
      for (const f of ritual.unfixed) {
        const a = f.advisories.find((x) => !x.fixed) ?? f.advisories[0];
        L.push(`  ${' '.repeat(10)}${c.coral('✕')} ${pad(c.soft(`${f.name} ${c.muted(f.version)}`), 30)} ${c.muted(a.id)}  ${c.muted(a.summary.slice(0, 44))}`);
      }
      L.push('');
    }
  }
  const s = ritual.state;
  const glyph = { closed: '●', half: '◐', open: '○' }[s.key];
  const col = { closed: 'bright', half: 'teal', open: 'coral' }[s.key];
  L.push(`  ${pad(c.gold('STATE'), 16)}${c[col](`${glyph} ${s.label} · ${s.note}`, true)}   ${c.muted(food.length ? `${Math.round(ritual.coverage * 100)}% closed by the ritual · ${Math.round(ritual.fixable * 100)}% closable at all` : 'nothing to close')}`);
  L.push('');
  return L.join('\n');
}

export function scriptBlock(ritual) {
  const { overrides, bumps, majors } = ritual.overrides;
  if (!Object.keys(overrides).length && !Object.keys(bumps).length) return '';
  const L = [`  ${c.gold('THE SCRIPT', true)} ${c.muted('— merge into package.json, then `npm install` and run your tests')}`, ''];
  const json = JSON.stringify({ dependencies: bumps, overrides }, null, 2).split('\n');
  for (const line of json) L.push(`    ${c.soft(line)}`);
  if (majors.length) {
    L.push('', `  ${c.coral('!')} ${c.muted('major-version jumps — the parent may not accept these; prefer upgrading the act itself:')}`);
    L.push(`    ${c.muted(majors.join(' · '))}`);
  }
  L.push('');
  return L.join('\n');
}
