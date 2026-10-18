# DECISION-001 — Build the Theatre of Dependencies before kintsugi

**Date:** 2026-10-18 · **Decided by:** Mazze LeCzzare Frazer · **Drafted with:** the `high-signal-engine` skill (first dogfood run)
**Source:** the two instruments proposed on the *Intentional Fragility* spine page
(`blog/mazze-leczzare-blog/public/intentional-fragility/index.html`).

## Summary

- **Build the Theatre of Dependencies first.** It runs on input every project already has (a lockfile or SBOM) and real public data (OSV.dev), and its output is something you act on the same day: which direct dependencies to fix, in what order, and the `package.json` patch that does it.
- **Defer kintsugi.** The circuit breaker only means something inside a live agent harness with real tools failing under real load. Any stand-alone demo would be simulated, which breaks the promise to publish no simulated assurance.

## Insights

- **Only one of the two can be honest in isolation.** Theatre's animation can replay real solver steps over a real graph. kintsugi's demo, like the page's own panel, would be a scripted state machine with a random eject reason. The spine's line "the break is the record" doesn't survive a fake break.
- **The page's metaphor maps onto a real algorithm.** Tero et al.'s adaptive network competes rival routes when γ > 1, which is exactly "converge on a minimal set of roots". Run as multi-commodity flow over each advisory's *ancestor* subgraph, it respects dependency direction. A naive undirected resistor network would credit packages that can't actually deliver the vulnerability.
- **The organism proposes; an exact cut verifies.** Physarum consolidates each advisory's flow onto one entrance, but upgrading that entrance does not close an advisory that also enters elsewhere (in the fixture, `qs` comes in through both `express` and `request`). Coverage is therefore computed exactly: an advisory closes only when every entrance it can use is in the ritual. The report names those shared entrances instead of rounding them away.
- **Both proposals overclaim on the live page today.** It lists kintsugi as "Python · verified" and both instruments link "→ source & demo" to the bare GitHub profile. Neither existed when this was decided. Building Theatre makes one of those links true; the other still needs correcting on the page.

## Sources

- [Tero et al., *Rules for Biologically Inspired Adaptive Network Design*, Science 327:439 (2010)](https://pubmed.ncbi.nlm.nih.gov/20093467/) and its [supplementary material](https://math.mit.edu/~dunkel/Teach/18.S995_2014F/paper_suggestions/science_tero_sm.pdf): the conductivity model and the γ > 1 competition regime.
- [OSV.dev API: POST /v1/querybatch](https://google.github.io/osv.dev/post-v1-querybatch/): the batch shape and the ids-only response, which is why records are then fetched one by one via `/v1/vulns/{id}`.
- [npm docs: `overrides` in package.json](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#overrides): scoped overrides (`{"express": {"qs": "^6.7.3"}}`) and the `EOVERRIDE` rule that forces bumps for direct dependencies.
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document): the base-score formula and the float-safe `Roundup` used in `src/severity.mjs`.

## Verification (2026-10-18)

- On `fixtures/vulnerable-shop`, the packages carrying their own advisory match `npm audit` exactly: 30 of 30. npm audit's 5 extra entries (`argparse`, `chokidar`, `mkdirp`, `mocha`, `optimist`) only reach an advisory through a child.
- `blog/mazze-leczzare-blog` and `skills/claude-code-skills/site` both come back clean, and `npm audit` agrees (0 and 0).

## Action

- Done: `tools/theatre-of-dependencies`, a zero-dependency Node CLI plus a standalone HTML stage.
- Open: fix the spine page's kintsugi claim ("Python · verified") and point the Theatre link at this repo once it has a remote.
- Later: kintsugi as a module in `temenos` or `delegation-harness`, where real tools eject under real load and the eject-reason taxonomy has data to record.
