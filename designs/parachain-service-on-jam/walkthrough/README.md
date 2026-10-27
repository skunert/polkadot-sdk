# Speculative messaging on JAM: animated walkthrough

An interactive, step-by-step animation of speculative messaging over the
Parachain Service, following the inclusion tier. Written for readers who know
polkadot-sdk but are new to the messaging design.

- **Part I · The big picture**: one full round trip (channel setup, A sends,
  B consumes, credit flows back) at actor level. Compressed mechanisms are
  marked ①–⑤ on the scene.
- **Part II · Under the hood**: rewinds to the open channel and opens each
  mechanism on block N's messages: ① commit, ② settle, ③ fetch & verify,
  ④ consume & lift, ⑤ settlement check.

It complements `../parachain-service-on-jam.md` and the speculative messaging
design document.

## Run

```bash
npm install
npm run dev        # http://localhost:5173
npm run build      # static site in dist/
```

Keys: → / Space plays the next beat (Part I steps are split into beats, one
per bullet in the panel), ← goes back one beat, R replays the current beat. The panel's buttons (I, ①–⑤)
jump between parts and chapters; `#<n>` in the URL opens step n.

## Layout

- `index.html`: the SVG scene, every animated element has an `id`.
- `src/steps.js`: panel narration and spec references per step.
- `src/main.js`: one builder per step, all on a single GSAP timeline. Whatever
  a step shows stays on screen when it ends; builders return their transient
  elements, which the next step clears. The rewind into Part II captures the
  scene at an earlier step and tweens back to it (`restore`). Builders use only
  `set`/`to` on elements that are animated more than once, so seeking backwards
  stays exact.
- `scripts/shoot.mjs`: screenshots of every step's end state (Playwright),
  `node scripts/shoot.mjs <url> <outdir>`.
