// OSV.dev client: querybatch for ids, then GET /v1/vulns/{id} for full records.
// Every response is cached on disk under a hashed filename — package names come
// from an untrusted lockfile and never become paths.

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';

const API = 'https://api.osv.dev/v1';
const BATCH = 1000;          // OSV's documented per-request query limit
const QUERY_TTL_MS = 24 * 3600 * 1000;

const h = (s) => createHash('sha256').update(s).digest('hex').slice(0, 32);

export class OSV {
  constructor({ cacheDir, offline = false, log = () => {} }) {
    this.dir = cacheDir; this.offline = offline; this.log = log;
    this.stats = { fetched: 0, cached: 0, missing: 0 };
    mkdirSync(join(cacheDir, 'q'), { recursive: true });
    mkdirSync(join(cacheDir, 'v'), { recursive: true });
  }

  #read(kind, key, ttl) {
    const f = join(this.dir, kind, `${h(key)}.json`);
    if (!existsSync(f)) return null;
    if (ttl && !this.offline && Date.now() - statSync(f).mtimeMs > ttl) return null;
    try { return JSON.parse(readFileSync(f, 'utf8')); } catch { return null; }
  }
  #write(kind, key, val) { writeFileSync(join(this.dir, kind, `${h(key)}.json`), JSON.stringify(val)); }

  async #post(path, body) {
    const res = await fetch(`${API}${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`OSV ${path} → HTTP ${res.status}`);
    return res.json();
  }

  async #get(path) {
    const res = await fetch(`${API}${path}`, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`OSV ${path} → HTTP ${res.status}`);
    return res.json();
  }

  static queryFor(node) {
    if (node.ecosystem && node.version) return { package: { name: node.name, ecosystem: node.ecosystem }, version: node.version };
    if (node.purl && /@[^/]+$/.test(node.purl)) return { package: { purl: node.purl } };
    return null;
  }

  // nodes → Map(nodeId → [{id, modified}])
  async affecting(nodes) {
    const out = new Map(), todo = [];
    for (const n of nodes) {
      const q = OSV.queryFor(n);
      if (!q) continue;
      const key = JSON.stringify(q);
      const hit = this.#read('q', key, QUERY_TTL_MS);
      if (hit) { out.set(n.id, hit); this.stats.cached++; }
      else if (this.offline) { this.stats.missing++; }
      else todo.push({ n, q, key });
    }
    for (let i = 0; i < todo.length; i += BATCH) {
      const chunk = todo.slice(i, i + BATCH);
      this.log(`querying OSV for ${chunk.length} packages`);
      const { results } = await this.#post('/querybatch', { queries: chunk.map((t) => t.q) });
      for (let j = 0; j < chunk.length; j++) {
        // Paginated results (>1000 vulns for one package) are vanishingly rare for
        // a single version; the first page is kept and the truncation noted.
        const vulns = results[j]?.vulns ?? [];
        if (results[j]?.next_page_token) this.log(`note: ${chunk[j].n.name} has more advisories than one page`);
        out.set(chunk[j].n.id, vulns);
        this.#write('q', chunk[j].key, vulns);
        this.stats.fetched++;
      }
    }
    return out;
  }

  async records(refs) {
    const want = new Map();
    for (const r of refs) if (!want.has(r.id) || (r.modified ?? '') > (want.get(r.id) ?? '')) want.set(r.id, r.modified ?? '');
    const out = new Map(), todo = [];
    for (const [id, modified] of want) {
      const hit = this.#read('v', id);
      if (hit && (this.offline || !modified || (hit.modified ?? '') >= modified)) out.set(id, hit);
      else if (this.offline) this.stats.missing++;
      else todo.push(id);
    }
    if (todo.length) this.log(`fetching ${todo.length} advisories`);
    let next = 0;
    const worker = async () => {
      while (next < todo.length) {
        const id = todo[next++];
        const rec = await this.#get(`/vulns/${encodeURIComponent(id)}`);
        this.#write('v', id, rec); out.set(id, rec);
      }
    };
    await Promise.all(Array.from({ length: Math.min(8, todo.length) }, worker));
    return out;
  }
}
