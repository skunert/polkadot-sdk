import { gsap } from 'gsap'
import { MotionPathPlugin } from 'gsap/MotionPathPlugin'
import { DrawSVGPlugin } from 'gsap/DrawSVGPlugin'
import { steps } from './steps.js'

gsap.registerPlugin(MotionPathPlugin, DrawSVGPlugin)
gsap.defaults({ ease: 'power2.inOut' })

// ── Timeline helpers ────────────────────────────────────────────
// Every state change is a tween on the one master timeline, so seeking
// backwards restores earlier states for free. No callbacks, no DOM writes.
//
// Rule: whatever a step shows stays on screen when the step ends. A builder
// returns the selectors of its transient elements (tokens, trails, fold
// lines); they are cleared as the first action of the next step.

const fadeIn = (tl, sel, pos) => tl.to(sel, { opacity: 1, duration: 0.4 }, pos)
const fadeOut = (tl, sel, pos) => tl.to(sel, { opacity: 0, duration: 0.3 }, pos)

function swap(tl, from, to, pos) {
	tl.to(from, { opacity: 0, duration: 0.3 }, pos)
	tl.to(to, { opacity: 1, duration: 0.3 }, '<')
}

function pulse(tl, sel, pos, scale = 1.18) {
	tl.to(sel, {
		scale,
		transformOrigin: '50% 50%',
		duration: 0.18,
		yoyo: true,
		repeat: 1,
		ease: 'power1.inOut',
	}, pos)
}

function flash(tl, sel, pos) {
	tl.to(sel, { strokeWidth: 4, duration: 0.15, yoyo: true, repeat: 1 }, pos)
}

function travel(tl, token, path, duration = 0.9, pos) {
	tl.to(token, { motionPath: { path }, duration, ease: 'power1.inOut' }, pos)
}

// A visible copy of each settlement motion path, drawn behind its token.
const trails = document.getElementById('trails')
for (const id of ['pA1', 'pA2', 'pA3', 'pA4', 'pA5', 'pB1', 'pB2', 'pB3', 'pB4', 'pB5']) {
	const t = document.getElementById(id).cloneNode()
	t.id = `trail-${id}`
	t.setAttribute('class', `trail ${id[1].toLowerCase()}`)
	trails.append(t)
}

function travelWithTrail(tl, token, path, duration) {
	// A trail may have been faded out after an earlier use; show it again.
	tl.set(`#trail-${path}`, { opacity: 0.6 })
	travel(tl, token, `#${path}`, duration)
	tl.fromTo(`#trail-${path}`,
		{ drawSVG: '0%' },
		{ drawSVG: '100%', duration, ease: 'power1.inOut' }, '<')
}

// Token from a runtime's StreamsRoot via its collator through Refine and
// Accumulate into its settlement ring. `p` is the path prefix, `c` the chain;
// `last` picks the final path segment, which ends at the ring slot `ring`.
// The token becomes the ring entry and the head caret moves to `headX`;
// the route stays drawn as a trail.
function settleRoot(tl, c, p, { tok = `#tok${c}`, last = 4, ring, headX = 44 } = {}) {
	const l = c.toLowerCase()
	ring ??= `#${l}-ring0`
	tl.set(tok, { opacity: 1, x: c === 'A' ? 434 : 1054, y: 70 })
	travelWithTrail(tl, tok, `${p}1`, 1.0)
	flash(tl, `#col${c} rect`)
	travelWithTrail(tl, tok, `${p}2`, 1.0)
	flash(tl, '#refine rect')
	travelWithTrail(tl, tok, `${p}3`, 0.6)
	flash(tl, '#accumulate rect')
	travelWithTrail(tl, tok, `${p}${last}`, 0.9)
	fadeOut(tl, tok)
	tl.to(ring, { opacity: 1, duration: 0.3 }, '<')
	pulse(tl, ring, '<', 1.25)
	tl.to(`#${l}-head`, { x: headX, duration: 0.5 })
	fadeIn(tl, `#${l}-tail`, '<') // the ring has an oldest entry
	return [1, 2, 3, last].map((i) => `#trail-${p}${i}`)
}

const dropLeaf = (tl, sel, pos) =>
	tl.fromTo(sel, { opacity: 0, y: -40 }, { opacity: 1, y: 0, duration: 0.6, ease: 'back.out(1.6)' }, pos)

// After a block, its collator pulls the block's sends via outbound_messages()
// into its node-local archive: leaf copies fly from the stream row into the
// archive chips. Each item is [leaf index, from x, from y, to x].
function archiveSends(tl, c, items) {
	fadeIn(tl, `#${c}-archive`)
	items.forEach(([i, fx, fy, tx], k) => {
		tl.set(`#fly-${c}${i}`, { opacity: 1, x: fx, y: fy }, k ? '-=0.5' : '+=0.1')
		tl.to(`#fly-${c}${i}`, { x: tx, y: 411, duration: 0.8 })
		fadeOut(tl, `#fly-${c}${i}`)
		fadeIn(tl, `#arc-${c}${i}`, '<')
	})
	flash(tl, `#col${c.toUpperCase()} rect`)
}

// One send: the call is logged, the credit gate ticks up, and the message
// flies from the log into its slot as a pending leaf of this block.
function sendData(tl, i, slotX, fillWidth) {
	const logX = i === 1 ? 212 : 362
	fadeIn(tl, `#send-log${i}`, '+=0.2')
	pulse(tl, '#a-credit-fill', undefined, 1.15)
	tl.to('#a-credit-fill', { attr: { width: fillWidth }, duration: 0.3 })
	swap(tl, `#a-cr-${i}`, `#a-cr-${i + 1}`, '<')
	tl.set(`#fly${i}`, { opacity: 1, x: logX, y: 284 })
	tl.to(`#fly${i}`, { x: slotX, y: 138, duration: 0.7, ease: 'power2.inOut' })
	fadeOut(tl, `#fly${i}`)
	tl.fromTo(`#a-leaf${i}`, { opacity: 0 }, { opacity: 1, duration: 0.3 }, '<')
}

// ── The script, one builder per step ─────────────────────────────

const build = {
	goal(tl) {
		tl.set('#goal', { opacity: 1 })
		tl.from(['#goal-kicker', '#goal-title', '#goal-sub'], { opacity: 0, y: 12, duration: 0.6, stagger: 0.15 })
		tl.from('#goal-text', { opacity: 0, y: 10, duration: 0.6 }, '+=0.2')
		tl.from('#goal-diagram', { opacity: 0, duration: 0.5 }, '+=0.2')
		tl.fromTo('#goal-arrow', { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.6 })
		tl.set('#goal-msg', { opacity: 1 })
		tl.to('#goal-msg', { motionPath: { path: '#goal-arrow' }, duration: 1.2, ease: 'power1.inOut' })
		fadeIn(tl, '#goal-rev', '+=0.2')
		tl.from('#goal-road', { opacity: 0, y: 10, duration: 0.6 }, '+=0.2')
		return ['#goal']
	},

	intro(tl) {
		tl.from(['#chainA', '#chainB', '#offchain-band', '#colA', '#colB', '#jam-frame', '#jam'], {
			opacity: 0,
			y: 16,
			duration: 0.6,
			stagger: 0.1,
			ease: 'power2.out',
		})
	},

	anatomy(tl) {
		tl.fromTo('#anatomy', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		tl.to('#an-id .k-punct', { fillOpacity: 1, duration: 0.3 })
		for (const k of ['kind', 'rcpt', 'dom', 'num']) {
			tl.to(`#an-id .k-${k}`, { fillOpacity: 1, duration: 0.3 }, '+=0.25')
			tl.fromTo(`#an-row-${k}`, { opacity: 0, x: -12 }, { opacity: 1, x: 0, duration: 0.35 }, '<')
		}
		tl.fromTo('#an-ack', { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.4 }, '+=0.4')
		fadeIn(tl, '#an-short', '+=0.3')
		return ['#anatomy']
	},

	open(tl) {
		dropLeaf(tl, '#a-leaf0')
		fadeIn(tl, '#a-phase-opening', '+=0.2')
	},

	commitA(tl) {
		tl.fromTo('#a-fold', { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.6 })
		swap(tl, '#a-root-0', '#a-root-1')
		pulse(tl, '#a-root-pill', '<')
		archiveSends(tl, 'a', [[0, 174, 138, 266]])
		return ['#a-fold', ...settleRoot(tl, 'A', 'pA')]
	},

	// A signed tx reaches B's runtime the same way A's inherent will later:
	// through B's collator, into B's next block.
	accept(tl) {
		fadeIn(tl, '#user')
		tl.set('#tx', { x: 1100, y: 395 })
		travel(tl, '#tx', '#pTx1', 1.0)
		tl.fromTo('#tx', { opacity: 0 }, { opacity: 1, duration: 0.3 }, '<')
		flash(tl, '#colB rect')
		travel(tl, '#tx', '#pTx2', 0.7)
		flash(tl, '#chainB .box')
		return ['#tx', '#user']
	},

	publishB(tl) {
		swap(tl, '#b-empty', '#b-channel')
		dropLeaf(tl, '#b-leaf0', '+=0.2')
		fadeIn(tl, '#b-leaf0-detail')
	},

	commitB(tl) {
		tl.fromTo('#b-fold', { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.6 })
		swap(tl, '#b-root-0', '#b-root-1')
		pulse(tl, '#b-root-pill', '<')
		archiveSends(tl, 'b', [[0, 794, 200, 886]])
		return ['#b-fold', ...settleRoot(tl, 'B', 'pB')]
	},

	notice(tl) {
		pulse(tl, ['#b-ring0', '#b-head'], undefined, 1.25)
		tl.fromTo('#read-line', { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.9 })
		flash(tl, '#colA rect')
		// The read line stays through the fetch, which uses T_B1.
	},

	fetch(tl) {
		fadeIn(tl, '#offchain-band-hi')
		tl.set('#req', { opacity: 1, x: 530, y: 383 })
		travel(tl, '#req', '#pReq', 1.0)
		flash(tl, '#colB rect')
		tl.set('#resp', { opacity: 1, x: 655, y: 410 }, '+=0.1')
		travel(tl, '#resp', '#pResp', 1.0)
		flash(tl, '#colA rect')
		fadeIn(tl, ['#a-fetched', '#fet-a0'], '<')
		fadeIn(tl, '#fet-a0-ok')
		// On-chain counterpart: what the chain holds is just these hashes.
		fadeIn(tl, ['#a-32', '#b-32'], '+=0.3')
		pulse(tl, ['#a-ring0', '#b-ring0'], '<', 1.25)
		return [
			'#read-line', '#req', '#resp', '#offchain-band-hi', '#a-32', '#b-32',
			'#a-fetched', '#fet-a0', '#fet-a0-ok',
		]
	},

	import(tl) {
		tl.set('#inh', { opacity: 1, x: 290, y: 395 })
		travel(tl, '#inh', '#pInh', 0.8)
		swap(tl, '#a-phase-opening', '#a-phase-open')
		swap(tl, '#a-ack-none', '#a-ack-reg', '+=0.3')
		return ['#inh']
	},

	summary(tl) {
		fadeIn(tl, ['#halo-a', '#halo-b'])
		pulse(tl, ['#a-ring0', '#b-ring0'], '<', 1.25)
		pulse(tl, ['#a-root-pill', '#b-root-pill'], '+=0.1')
		return ['#halo-a', '#halo-b']
	},

	// ── Stage 1 · A authors a block with data ──

	's1-intro'(tl) {
		fadeOut(tl, '#a-req-line') // consumption records are per block
		fadeIn(tl, '#a-block', '<')
		flash(tl, '#colA rect')
		flash(tl, '#chainA .box')
		fadeIn(tl, '#a-credit', '+=0.1')
	},

	's1-send'(tl) {
		fadeIn(tl, '#a-split')
		sendData(tl, 1, 228, 15)
		sendData(tl, 2, 282, 22.5)
		return ['#send-log1', '#send-log2']
	},

	's1-bag'(tl) {
		tl.fromTo('#bag', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		tl.fromTo('#mmr-l1', { opacity: 0, y: -20 }, { opacity: 1, y: 0, duration: 0.4 }, '+=0.3')
		tl.fromTo(['#mmr-e0', '#mmr-e1'], { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.4 })
		fadeIn(tl, '#mmr-n01', '-=0.1')
		tl.fromTo('#mmr-l2', { opacity: 0, y: -20 }, { opacity: 1, y: 0, duration: 0.4 }, '+=0.3')
		fadeIn(tl, '#mmr-peaks', '+=0.2')
		pulse(tl, ['#mmr-n01', '#mmr-l2'], '<')
		tl.fromTo(['#mmr-b0', '#mmr-b1'], { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.5 }, '+=0.2')
		fadeIn(tl, '#mmr-root')
		pulse(tl, '#mmr-root', undefined, 1.08)
	},

	's1-fold'(tl) {
		fadeIn(tl, '#bag-right')
		tl.set('#bag-fly', { opacity: 1, x: 320, y: 393 }, '+=0.2')
		tl.to('#bag-fly', { x: 710, y: 455, duration: 1 })
		fadeOut(tl, '#bag-fly')
		swap(tl, '#trie-leaf-old', '#trie-leaf-new', '<')
		tl.fromTo('#trie-edge-hot', { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.5 })
		swap(tl, '#trie-root-0', '#trie-root-1')
		pulse(tl, '#trie-root-g', '<', 1.1)
		fadeIn(tl, '#bag-out', '+=0.3')
		return ['#bag']
	},

	's1-outputs'(tl) {
		swap(tl, '#a-root-1', '#a-root-2')
		pulse(tl, '#a-root-pill', '<')
		fadeIn(tl, '#a-digest')
		archiveSends(tl, 'a', [[1, 228, 138, 310], [2, 282, 138, 354]])
	},

	's1-summary'(tl) {
		pulse(tl, ['#a-leaf1', '#a-leaf2'])
		pulse(tl, ['#arc-a1', '#arc-a2'], '+=0.1', 1.2)
		pulse(tl, '#a-root-pill', '+=0.1')
		pulse(tl, '#a-ring0', '+=0.1', 1.25)
	},

	// ── Stage 2 · Block N through JAM ──

	's2-package'(tl) {
		flash(tl, '#colA rect')
		tl.set('#wp', { opacity: 1, x: 290, y: 395 })
		travelWithTrail(tl, '#wp', 'pA2', 1.2)
		flash(tl, '#refine rect')
		fadeOut(tl, '#wp')
		fadeIn(tl, '#refine-wp', '<')
		return ['#trail-pA2']
	},

	's2-refine'(tl) {
		tl.fromTo('#rf-card', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		for (let i = 0; i <= 7; i++) {
			tl.fromTo(`#rf-r${i}`, { opacity: 0, x: -10 }, { opacity: 1, x: 0, duration: 0.3 }, i ? '+=0.15' : '+=0.2')
		}
		pulse(tl, '#rf-r6', undefined, 1.03)
		fadeIn(tl, '#rf-foot', '+=0.2')
		return ['#rf-card']
	},

	's2-join'(tl) {
		fadeOut(tl, '#refine-wp')
		tl.set('#dg', { opacity: 1, x: 580, y: 560 })
		travelWithTrail(tl, '#dg', 'pA3', 1.0)
		fadeIn(tl, '#join-badges', '-=0.5')
		flash(tl, '#accumulate rect')
		fadeOut(tl, '#dg')
		fadeIn(tl, '#acc-digest', '<')
		return ['#trail-pA3', '#join-badges']
	},

	's2-accumulate'(tl) {
		tl.fromTo('#ac-card', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		for (let i = 0; i <= 7; i++) {
			tl.fromTo(`#ac-r${i}`, { opacity: 0, x: -10 }, { opacity: 1, x: 0, duration: 0.3 }, i ? '+=0.2' : '+=0.2')
		}
		pulse(tl, '#ac-r5', undefined, 1.03)
		fadeIn(tl, '#ac-foot', '+=0.2')
		return ['#ac-card']
	},

	's2-enact'(tl) {
		fadeOut(tl, '#acc-digest')
		tl.set('#tokA2', { opacity: 1, x: 580, y: 660 })
		travelWithTrail(tl, '#tokA2', 'pA5', 1.0)
		fadeOut(tl, '#tokA2')
		fadeIn(tl, '#a-ring1', '<')
		pulse(tl, '#a-ring1', '<', 1.25)
		tl.to('#a-head', { x: 88, duration: 0.5 })
		swap(tl, '#a-block', '#a-block-ok')
		pulse(tl, '#a-block-ok', '<')
		return ['#trail-pA5']
	},

	's2-summary'(tl) {
		pulse(tl, ['#a-ring0', '#a-ring1'], undefined, 1.25)
		pulse(tl, ['#arc-a1', '#arc-a2'], '+=0.1', 1.2)
	},

	// ── Stage 3 · B fetches the messages ──

	's3-notice'(tl) {
		pulse(tl, ['#a-ring1', '#a-head'], undefined, 1.25)
		tl.fromTo('#read-line2', { drawSVG: '0%' }, { drawSVG: '100%', duration: 1 })
		flash(tl, '#colB rect')
	},

	's3-fetch'(tl) {
		fadeIn(tl, '#offchain-band-hi')
		tl.set('#mreq', { opacity: 1, x: 670, y: 383 })
		travel(tl, '#mreq', '#pMReq', 1.0)
		flash(tl, '#colA rect')
		pulse(tl, ['#arc-a0', '#arc-a1', '#arc-a2'], '<', 1.2) // served from the archive
		tl.set('#mresp', { opacity: 1, x: 545, y: 410 }, '+=0.1')
		travel(tl, '#mresp', '#pMResp', 1.0)
		flash(tl, '#colB rect')
		fadeIn(tl, ['#b-fetched', '#fet-b0', '#fet-b1', '#fet-b2'], '<')
		return ['#mreq', '#mresp', '#offchain-band-hi', '#read-line2']
	},

	's3-verify'(tl) {
		tl.fromTo('#vf-card', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		for (let i = 0; i <= 3; i++) {
			tl.fromTo(`#vf-r${i}`, { opacity: 0, x: -10 }, { opacity: 1, x: 0, duration: 0.3 }, '+=0.25')
		}
		pulse(tl, '#vf-r3', undefined, 1.03)
		fadeIn(tl, '#vf-foot', '+=0.2')
		fadeIn(tl, '#fet-b-ok', '<') // the staged payloads are now trusted
		return ['#vf-card']
	},

	// ── Stage 4 · B consumes them ──

	's4-inherent'(tl) {
		fadeIn(tl, '#b-block')
		flash(tl, '#colB rect')
		tl.set('#inhB', { opacity: 1, x: 910, y: 395 })
		travel(tl, '#inhB', '#pTx2', 0.8)
		fadeOut(tl, ['#b-fetched', '#fet-b0', '#fet-b1', '#fet-b2', '#fet-b-ok'], '<')
		return ['#inhB']
	},

	's4-consume'(tl) {
		flash(tl, '#chainB .box')
		dropLeaf(tl, '#b-in0', '+=0.1')
		dropLeaf(tl, '#b-in1', '-=0.3')
		dropLeaf(tl, '#b-in2', '-=0.3')
		swap(tl, '#b-front-0', '#b-front-3')
		fadeIn(tl, '#b-record', '+=0.3')
	},

	's4-summary'(tl) {
		pulse(tl, ['#b-in0', '#b-in1', '#b-in2'])
		pulse(tl, '#b-root-pill', '+=0.1') // unchanged: block M sent nothing
	},

	// ── Stage 5 · B's block settles ──

	's5-package'(tl) {
		flash(tl, '#colB rect')
		tl.set('#wpB', { opacity: 1, x: 910, y: 395 })
		travelWithTrail(tl, '#wpB', 'pB2', 1.2)
		flash(tl, '#refine rect')
		fadeOut(tl, '#wpB')
		fadeIn(tl, '#refine-wpB', '<')
		return ['#trail-pB2']
	},

	's5-refine'(tl) {
		tl.fromTo('#rf2-card', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		for (let i = 0; i <= 5; i++) {
			tl.fromTo(`#rf2-r${i}`, { opacity: 0, x: -10 }, { opacity: 1, x: 0, duration: 0.3 }, '+=0.25')
		}
		pulse(tl, '#rf2-r4', undefined, 1.03)
		fadeIn(tl, '#rf2-foot', '+=0.2')
		return ['#rf2-card']
	},

	's5-settle'(tl) {
		fadeOut(tl, '#refine-wpB')
		tl.set('#dgB', { opacity: 1, x: 580, y: 560 })
		travelWithTrail(tl, '#dgB', 'pB3', 1.0)
		flash(tl, '#accumulate rect')
		fadeOut(tl, '#dgB')
		fadeIn(tl, '#acc-digestB', '<')
		// Check 5: look the required root up in the sender's ring.
		tl.fromTo('#check-line', { drawSVG: '0%' }, { drawSVG: '100%', duration: 1 }, '+=0.2')
		pulse(tl, '#a-ring1', undefined, 1.3)
		fadeIn(tl, '#check-lbl')
		swap(tl, '#b-block', '#b-block-ok', '+=0.3')
		pulse(tl, '#b-block-ok', '<')
		return ['#trail-pB3', '#acc-digestB', '#check-line', '#check-lbl']
	},

	's5-summary'(tl) {
		pulse(tl, '#b-block-ok')
		pulse(tl, ['#b-in0', '#b-in1', '#b-in2'], '+=0.1')
		pulse(tl, '#a-ring1', '+=0.1', 1.25)
	},

	// ── Stage 6 · Credit flows back to A ──

	's6-publish'(tl) {
		fadeOut(tl, '#b-record')
		dropLeaf(tl, '#b-leaf1')
		swap(tl, '#b-leaf0-detail', '#b-leaf1-detail')
		tl.set('#b-fold', { opacity: 1 })
		tl.fromTo('#b-fold', { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.6 })
		swap(tl, '#b-root-1', '#b-root-2')
		pulse(tl, '#b-root-pill', '<')
		archiveSends(tl, 'b', [[1, 848, 200, 930]])
		return ['#b-fold']
	},

	's6-settle'(tl) {
		return settleRoot(tl, 'B', 'pB', { tok: '#tokB2', last: 5, ring: '#b-ring1', headX: 88 })
	},

	's6-read'(tl) {
		pulse(tl, ['#b-ring1', '#b-head'], undefined, 1.25)
		tl.fromTo('#read-line3', { drawSVG: '0%' }, { drawSVG: '100%', duration: 1 })
		flash(tl, '#colA rect')
		fadeIn(tl, '#offchain-band-hi')
		tl.set('#req2', { opacity: 1, x: 530, y: 383 })
		travel(tl, '#req2', '#pReq', 1.0)
		flash(tl, '#colB rect')
		pulse(tl, '#arc-b1', '<', 1.2)
		tl.set('#resp2', { opacity: 1, x: 655, y: 410 }, '+=0.1')
		travel(tl, '#resp2', '#pResp', 1.0)
		flash(tl, '#colA rect')
		fadeIn(tl, ['#a-fetched', '#fet-a1', '#fet-a1-ok'], '<')
		return ['#read-line3', '#req2', '#resp2', '#offchain-band-hi']
	},

	's6-import'(tl) {
		fadeOut(tl, ['#a-fetched', '#fet-a1', '#fet-a1-ok'])
		tl.set('#inh2', { opacity: 1, x: 290, y: 395 })
		travel(tl, '#inh2', '#pInh', 0.8)
		// The new block's init absorbed block N's leaves into the frontier.
		swap(tl, ['#a-leaf1', '#a-leaf2'], ['#a-leaf1s', '#a-leaf2s'])
		fadeOut(tl, '#a-split', '<')
		swap(tl, '#a-ack-reg-l1', '#a-ack-reg2', '+=0.2')
		tl.to('#a-credit-fill', { attr: { width: 0.01 }, duration: 0.5 })
		swap(tl, '#a-cr-3', '#a-cr-0', '<')
		fadeIn(tl, '#a-req2', '+=0.2')
		return ['#inh2']
	},

	's6-prune'(tl) {
		fadeOut(tl, ['#arc-a0', '#arc-a1', '#arc-a2'])
		fadeIn(tl, '#arc-a-pruned', '+=0.1')
	},

	's6-summary'(tl) {
		pulse(tl, ['#b-in0', '#b-in1', '#b-in2'])
		pulse(tl, '#a-cr-0', '+=0.1', 1.2)
		pulse(tl, ['#a-ring1', '#b-ring1'], '+=0.1', 1.25)
	},
}

const tl = gsap.timeline({ paused: true })
let leftovers = []
for (const s of steps) {
	tl.addLabel(s.id)
	if (leftovers.length) fadeOut(tl, leftovers)
	leftovers = build[s.id](tl) ?? []
	tl.to({}, { duration: 0.15 }) // breathing room before the step ends
}

const starts = steps.map((s) => tl.labels[s.id])
// End a hair before the next label: seeking exactly onto it would already
// fire the next step's zero-length sets.
const ends = steps.map((_, i) => (starts[i + 1] ?? tl.duration() + 1e-3) - 1e-3)

// ── Navigation ──────────────────────────────────────────────────

const $ = (id) => document.getElementById(id)
const stageNames = [...new Set(steps.map((s) => s.stage))]
const stageFirst = stageNames.map((n) => steps.findIndex((s) => s.stage === n))
const stageBtns = stageNames.map((name, k) => {
	const b = document.createElement('button')
	b.textContent = name === 'Overview' ? '★' : name.match(/Stage (\d+)/)[1]
	b.title = name
	b.addEventListener('click', () => go(stageFirst[k], true))
	$('stages').append(b)
	return b
})
const dots = steps.map((s, i) => {
	const b = document.createElement('button')
	b.title = s.title
	b.addEventListener('click', () => go(i, true))
	$('dots').append(b)
	return b
})

let cur = 0
let playing = null

function render() {
	const s = steps[cur]
	const k = stageNames.indexOf(s.stage)
	const inStage = steps.filter((t) => t.stage === s.stage).length
	$('stage').textContent = `${s.stage} · step ${cur - stageFirst[k] + 1}/${inStage}`
	stageBtns.forEach((b, j) => {
		b.classList.toggle('current', j === k)
		b.classList.toggle('done', j < k)
	})
	$('step-title').innerHTML = s.title
	$('step-body').innerHTML = s.body
	$('step-ref').innerHTML = s.ref ? `Spec: ${s.ref}` : ''
	dots.forEach((d, i) => {
		d.classList.toggle('done', i < cur)
		d.classList.toggle('current', i === cur)
		d.classList.toggle('other-stage', steps[i].stage !== s.stage)
	})
	$('prev').disabled = cur === 0
	$('next').disabled = cur === steps.length - 1
	history.replaceState(null, '', `#${cur}`)
}

// Animate step i from its start, or jump straight to its end state.
function go(i, animate) {
	playing?.kill()
	playing = null
	cur = i
	render()
	if (animate) {
		tl.seek(starts[i])
		playing = tl.tweenFromTo(starts[i], ends[i], { ease: 'none' })
	} else {
		tl.seek(ends[i])
	}
}

function next() {
	if (playing?.isActive()) return go(cur, false) // first press skips the animation
	if (cur < steps.length - 1) go(cur + 1, true)
}

function prev() {
	if (cur > 0) go(cur - 1, false)
}

$('next').addEventListener('click', next)
$('prev').addEventListener('click', prev)
$('replay').addEventListener('click', () => go(cur, true))

document.addEventListener('keydown', (e) => {
	if (['ArrowRight', ' ', 'PageDown', 'Enter'].includes(e.key)) next()
	else if (['ArrowLeft', 'PageUp', 'Backspace'].includes(e.key)) prev()
	else if (e.key === 'r' || e.key === 'R') go(cur, true)
	else if (e.key === 'Home') go(0, true)
	else return
	e.preventDefault()
})

// Deep links (#3) land on the finished state of that step.
const initial = Number.parseInt(location.hash.slice(1), 10)
if (initial > 0 && initial < steps.length) go(initial, false)
else go(0, true)

// Hook for the screenshot script.
window.__deck = { go, steps, tl, starts, ends }
