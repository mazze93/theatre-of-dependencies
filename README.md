# Theatre of Dependencies

> `seed` · v0.1.0 · Node ≥ 20 · zero dependencies

A slime mold reads your dependency graph and stages an **upgrade ritual**: the
smallest set of direct dependencies to act on, in order, with exactly how much
of your vulnerable surface each act closes, and the `package.json` patch that
does it.

```
theatre demo                      # bundled fixture, offline: the whole show
theatre scan .                    # your project: growth in the terminal, then the playbill
theatre stage .                   # …and the animated stage, opened in your browser
```

## What it does

1. **Terrain.** Reads an npm v2/v3 `package-lock.json` (resolving nested
   `node_modules` the way Node does) or a CycloneDX JSON SBOM (any ecosystem,
   via purl).
2. **Food.** Asks [OSV.dev](https://osv.dev) which installed versions have
   advisories. Each vulnerable package becomes a food source weighted by
   severity: CVSS v3 computed exactly where a vector exists, otherwise the
   advisory database's label.
3. **The organism.** A multi-commodity form of Tero et al.'s
   *Physarum* model (Science, 2010). Each food source pushes current toward
   your project through every dependency chain that can deliver it. Tubes
   that carry current thicken. With γ = 1.8, rival routes compete until one
   wins. Tubes that carry nothing starve. Typically about 7% of the terrain
   survives.
4. **The ritual.** The entrances, meaning the direct dependencies whose tubes
   survive, become acts, ordered by flux. **Coverage is computed exactly, not
   read off the organism.** An advisory counts as closed only when *every*
   direct dependency it can enter through is in the ritual. When the
   organism's choice leaves a shared entrance open, the report says so; when
   an exact greedy cut over the same budget beats it, that shows up as a
   "second opinion".
5. **The script.** For each act, an npm `overrides` block scoped under that
   act, so a fix lands only in the subtree the act claims. Vulnerable direct
   dependencies get a version bump instead, because npm rejects overriding a
   direct dependency (`EOVERRIDE`). Major-version jumps are flagged.
6. **The break is kept.** Advisories with no published fix are listed in coral
   and stay on the record. They aren't folded into a percentage.

**State** uses the three-state discipline from the spine: `CLOSED` when the
ritual closes ≥ 92% of the vulnerable surface, `HALF-OPEN` at ≥ 60%, and
`OPEN` below that.

## The stage

`theatre stage` writes a single self-contained HTML file and opens it. Every
animated frame is a recorded solver step; nothing is scripted.

| Phase | What you see |
|---|---|
| Overture | Every package and every tube, lit. The organism reaches everywhere. |
| Growth | Current flows home from the vulnerable packages; unfed tubes starve; rival routes compete. |
| Ritual | Act by act, gold lacquer runs out from the heart along each claimed vein and seals it (kintsugi); closed packages turn teal; the coverage numeral climbs. |
| Coda | What's left: the ritual's result, the unfixable packages in coral, and the script with a copy button. |

Keys: `space` play/pause · `←` `→` scrub · `R` replay · `H` clean mode (hides
the chrome for recording) · `1`–`9` jump to an act. Add `?clean` to the URL to
start in clean mode, or `?t=12.5` to seek and hold, which is useful for stills.

**Recording tip:** open the stage full-screen at 1600×940 or larger, press `H`,
then `R`, and record about 35 seconds.

## CLI

```
theatre scan  [path]     read a lockfile or SBOM, grow the organism, print the playbill
theatre stage [path]     the same, then write and open the animated stage (HTML)
theatre demo             run both on the bundled vulnerable-shop fixture, offline

  --prod              ignore devDependencies
  --max-acts <n>      longest ritual to stage (default 7)
  --gate open|half    exit 3 if the ritual leaves the project at or below this state
  --json              machine-readable result on stdout
  --write <file>      also write the script (bumps + overrides) as JSON
  --out <file>        stage file (default theatre-stage.html)
  --no-open           write the stage but don't open it
  --offline           advisory cache only; never touch the network
  --cache <dir>       advisory cache (default ~/.cache/theatre-of-dependencies)
  --no-anim           skip the terminal growth sequence
```

Exit codes: `0` ok · `1` error · `3` gate failed. Output honours `NO_COLOR` and
falls back to plain text when stdout isn't a TTY.

CI gate:

```yaml
- run: node path/to/theatre/bin/theatre.mjs scan . --no-anim --gate open
```

## Verified

- `npm test`: 9 tests covering CVSS against the FIRST formula, OSV range
  matching, nested lockfile resolution, route competition and starvation,
  exact-cut coverage, scoped overrides, `</script>` escaping of
  attacker-named packages, and the CLI exit codes.
- On the fixture, the set of packages carrying their own advisory matches
  `npm audit` exactly (30 of 30). See `docs/DECISION.md`.

## Security notes

- **Zero runtime dependencies.** Node built-ins only, so there is no supply
  chain to audit for the auditor.
- **What leaves the machine:** package names and versions, sent to
  `api.osv.dev` (Google). Use `--offline` with a warm cache for private
  projects you don't want to disclose.
- **The lockfile is untrusted input.** Cache filenames are hashed, never
  derived from package names. In the stage, data is JSON-escaped against
  `</script>` breakout and rendered with `textContent` only, and the page
  ships a CSP (`default-src 'none'`; inline script; Google Fonts only).
- **The stage makes no network calls** except the web fonts. It falls back to
  system fonts offline.

## Limits (stated, not hidden)

- The script is a starting point; run your tests after applying it.
  Overrides can push a transitive package past what its parent declares.
  Major jumps are flagged but not resolved.
- An act means "act on this entrance": bump it, override beneath it, or
  replace it. Whether simply upgrading the direct dependency pulls in the
  fixed transitive version isn't checked yet (that needs registry metadata).
- No support for npm v1 lockfiles, pnpm, yarn, or SPDX. CycloneDX covers
  other ecosystems for reading the graph, but the `overrides` script is
  npm-only.
- Severity weighting: the worst advisory counts fully and each further one
  adds a quarter. That's a judgment call, documented in `src/feed.mjs`.

## Layout

```
bin/theatre.mjs        CLI
src/graph.mjs          lockfile + CycloneDX → terrain
src/osv.mjs            OSV client + hashed on-disk cache
src/severity.mjs       CVSS v3.x base score, label fallback
src/semver.mjs         version ordering, fix-line selection
src/feed.mjs           advisories → weighted food
src/physarum.mjs       the organism (multi-commodity Tero model, PCG solver)
src/ritual.mjs         acts, exact-cut coverage, second opinion, overrides
src/render-term.mjs    terminal growth sequence + playbill
src/stage.mjs          stage data + safe embedding
stage/template.html    the stage
fixtures/vulnerable-shop/  2020-era storefront lockfile + OSV snapshot (offline demo)
docs/DECISION.md       why this, not kintsugi (high-signal-engine dogfood)
```

---

Part of the *Intentional Fragility* body of work, on the
[spine](https://mazzeleczzare.com/intentional-fragility/).
