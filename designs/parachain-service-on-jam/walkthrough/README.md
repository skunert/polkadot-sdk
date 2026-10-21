# Speculative messaging on JAM: animated walkthrough

An interactive, step-by-step animation of speculative messaging over the
Parachain Service, following the inclusion tier: channel setup, A authoring a
block, settlement on JAM, B fetching and consuming the messages, B's block
settling, and credit flowing back to A.

It complements `../parachain-service-on-jam.md` and the speculative messaging
design document.

## Run

```bash
npm install
npm run dev        # http://localhost:5173
npm run build      # static site in dist/
```

Keys: → / Space next step, ← back, R replay. The panel's stage buttons jump
between stages; `#<n>` in the URL opens step n.

## Layout

- `index.html`: the SVG scene, every animated element has an `id`.
- `src/steps.js`: panel narration and spec references per step.
- `src/main.js`: one builder per step, all on a single GSAP timeline. Whatever
  a step shows stays on screen when it ends; builders return their transient
  elements, which the next step clears.
- `scripts/shoot.mjs`: screenshots of every step's end state (Playwright),
  `node scripts/shoot.mjs <url> <outdir>`.
