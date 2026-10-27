import { gsap } from 'gsap'
import { MotionPathPlugin } from 'gsap/MotionPathPlugin'
import { DrawSVGPlugin } from 'gsap/DrawSVGPlugin'
import { steps, chips } from './steps.js'

gsap.registerPlugin(MotionPathPlugin, DrawSVGPlugin)
gsap.defaults({ ease: 'power2.inOut' })

// ── Timeline helpers ────────────────────────────────────────────
// Every state change is a tween on the one master timeline, so seeking
// backwards restores earlier states for free. No callbacks, no DOM writes.
//
// Rule: whatever a step shows stays on screen when the step ends. A builder
// returns the selectors of its transient elements (tokens, trails, fold
// lines); they are cleared as the first action of the next step.
//
// Elements are animated in several parts of the walkthrough (overview, deep
// dive, replay), so builders only use `set` and `to`: a `from`/`fromTo` on a
// reused element would leak its start state into earlier steps when seeking
// back. The exceptions animate elements that appear exactly once (cards).

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

// Briefly thicken a border. autoRound is off: GSAP rounds px values by default,
// which would leave a 1.5 px border at 2 px after the flash.
function flash(tl, sel, pos) {
	tl.to(sel, { strokeWidth: 4, duration: 0.15, yoyo: true, repeat: 1, autoRound: false }, pos)
}

function travel(tl, token, path, duration = 0.9, pos) {
	tl.to(token, { motionPath: { path }, duration, ease: 'power1.inOut' }, pos)
}

// Draw a line from nothing. Lines start undrawn (see the initial state below).
function drawLine(tl, sel, duration = 0.6, pos, opacity = 1) {
	tl.set(sel, { opacity, drawSVG: '0%' }, pos)
	tl.to(sel, { drawSVG: '100%', duration }, '<')
}

// A new leaf fades in at its slot.
const addLeaf = (tl, sel, pos) => {
	tl.set(sel, { opacity: 0 }, pos)
	tl.to(sel, { opacity: 1, duration: 0.5 }, '<')
}

// A token fades in at its start point before it travels anywhere.
const appear = (tl, sel, x, y, pos) => {
	tl.set(sel, { opacity: 0, x, y }, pos)
	tl.to(sel, { opacity: 1, duration: 0.25 }, '<')
}

// Beats: pause points inside a step. Each press of → plays one beat, and the
// panel reveals the step's bullets one per beat. `clear` lists transients of
// the beat just finished; they fade as the first action of the next beat.
let beatMarks = []
function beat(tl, clear) {
	beatMarks.push(tl.duration())
	if (clear?.length) fadeOut(tl, clear)
}

// ①–⑤: shows (first time) and highlights the marker of a mechanism.
function marker(tl, n, pos) {
	tl.to(`#mk${n}`, { opacity: 1, duration: 0.3 }, pos)
	pulse(tl, `#mk${n}`, '<', 1.5)
}

// A visible copy of each settlement motion path, drawn behind its token.
const trails = document.getElementById('trails')
for (const id of ['pA1', 'pA2', 'pA3', 'pA4', 'pA5', 'pB1', 'pB2', 'pB3', 'pB4', 'pB5']) {
	const t = document.getElementById(id).cloneNode()
	t.id = `trail-${id}`
	t.setAttribute('class', `trail ${id[1].toLowerCase()}`)
	trails.append(t)
}

// Initial state, outside the timeline: every reusable line starts undrawn.
gsap.set('.trail, .fold, .read-line, .check-line', { drawSVG: '0%' })

function travelWithTrail(tl, token, path, duration) {
	tl.set(`#trail-${path}`, { opacity: 0.6, drawSVG: '0%' })
	travel(tl, token, `#${path}`, duration)
	tl.to(`#trail-${path}`, { drawSVG: '100%', duration, ease: 'power1.inOut' }, '<')
}

// Token from a runtime's StreamsRoot via its collator through Refine and
// Accumulate into its settlement ring. `p` is the path prefix, `c` the chain;
// `last` picks the final path segment, which ends at the ring slot `ring`.
// The token becomes the ring entry and the head caret moves to `headX`;
// the route stays drawn as a trail. `speed` < 1 plays it compressed.
function settleRoot(tl, c, p, { tok = `#tok${c}`, last = 4, ring, headX = 44, speed = 1 } = {}) {
	const l = c.toLowerCase()
	ring ??= `#${l}-ring0`
	appear(tl, tok, c === 'A' ? 434 : 1054, 70)
	travelWithTrail(tl, tok, `${p}1`, 1.0 * speed)
	flash(tl, `#col${c} rect`)
	travelWithTrail(tl, tok, `${p}2`, 1.0 * speed)
	flash(tl, '#refine rect')
	travelWithTrail(tl, tok, `${p}3`, 0.6 * speed)
	flash(tl, '#accumulate rect')
	travelWithTrail(tl, tok, `${p}${last}`, 0.9 * speed)
	fadeOut(tl, tok)
	tl.to(ring, { opacity: 1, duration: 0.3 }, '<')
	pulse(tl, ring, '<', 1.25)
	tl.to(`#${l}-head`, { x: headX, duration: 0.5 * speed })
	fadeIn(tl, `#${l}-tail`, '<') // the ring has an oldest entry
	return [1, 2, 3, last].map((i) => `#trail-${p}${i}`)
}

// After a block, its collator pulls the block's sends via outbound_messages()
// into its node-local archive: leaf copies fly from the stream row into the
// archive chips. Each item is [leaf index, from x, from y, to x].
function archiveSends(tl, c, items, speed = 1) {
	fadeIn(tl, `#${c}-archive`)
	const at = tl.duration() + 0.1 // all copies leave together
	const arrive = at + 0.25 + 0.8 * speed
	for (const [i, fx, fy, tx] of items) {
		appear(tl, `#fly-${c}${i}`, fx, fy, at)
		tl.to(`#fly-${c}${i}`, { x: tx, y: 427, duration: 0.8 * speed }, at + 0.25)
		tl.to(`#fly-${c}${i}`, { opacity: 0, duration: 0.3 }, arrive)
		tl.to(`#arc-${c}${i}`, { opacity: 1, duration: 0.4 }, arrive)
	}
	flash(tl, `#col${c.toUpperCase()} rect`)
}

// One send: the call is logged, the credit gate ticks up, and the message
// flies from the log into its slot as a pending leaf of this block.
function sendData(tl, i, slotX, fillWidth, speed = 1) {
	const logX = i === 1 ? 212 : 362
	fadeIn(tl, `#send-log${i}`, '+=0.2')
	pulse(tl, '#a-credit-fill', undefined, 1.15)
	tl.to('#a-credit-fill', { attr: { width: fillWidth }, duration: 0.3 })
	swap(tl, `#a-cr-${i}`, `#a-cr-${i + 1}`, '<')
	appear(tl, `#fly${i}`, logX, 294)
	tl.to(`#fly${i}`, { x: slotX, y: 138, duration: 0.7 * speed })
	fadeOut(tl, `#fly${i}`)
	tl.to(`#a-leaf${i}`, { opacity: 1, duration: 0.3 }, '<')
}

// Off-chain request/response between the collators.
function exchange(tl, req, reqPath, reqAt, resp, respPath, respAt, server) {
	fadeIn(tl, '#offchain-band-hi')
	appear(tl, req, reqAt[0], reqAt[1])
	travel(tl, req, reqPath, 1.0)
	flash(tl, `${server} rect`)
	appear(tl, resp, respAt[0], respAt[1], '+=0.1')
	travel(tl, resp, respPath, 1.0)
}

// ── Rewinds: restore the scene as it was at an earlier step ─────
// Part II and III start from earlier moments of Part I. `restore` captures
// the scene at the clean end of that step (after its transients cleared) and
// tweens every element that differs now back to it. Markers stay as they are:
// once introduced they remain as anchors.

const tracked = [...document.querySelectorAll('#scene [id]')]
	.filter((el) => !el.closest('#paths') && !el.closest('.marker'))

function capture() {
	return tracked.map((el) => ({
		opacity: Number(gsap.getProperty(el, 'opacity')),
		x: Number(gsap.getProperty(el, 'x')) || 0,
		y: Number(gsap.getProperty(el, 'y')) || 0,
		scale: Number(gsap.getProperty(el, 'scale')) || 1,
		dash: el.style.strokeDasharray,
		offset: el.style.strokeDashoffset,
		width: el.id === 'a-credit-fill' ? Number(el.getAttribute('width')) : null,
	}))
}

const clean = {} // step id → timeline time of its clean end state

function restore(tl, stepId) {
	const now = tl.duration()
	tl.seek(clean[stepId] - 1e-4, false)
	const target = capture()
	tl.seek(now, false)
	const current = capture()
	const at = tl.duration()
	const round = (o) => (o < 0.01 ? 0 : o > 0.99 ? 1 : o)
	tracked.forEach((el, i) => {
		const t = target[i]
		const c = current[i]
		const vars = {}
		if (Math.abs(t.opacity - c.opacity) > 0.01) vars.opacity = round(t.opacity)
		if (Math.abs(t.x - c.x) > 0.5) vars.x = t.x
		if (Math.abs(t.y - c.y) > 0.5) vars.y = t.y
		if (Math.abs(t.scale - c.scale) > 0.01) vars.scale = t.scale
		if (t.width !== null && Math.abs(t.width - c.width) > 0.1) vars.attr = { width: t.width }
		if (Object.keys(vars).length) tl.to(el, { ...vars, duration: 0.8 }, at)
		if (t.dash !== c.dash || t.offset !== c.offset) {
			tl.set(el, { strokeDasharray: t.dash || 'none', strokeDashoffset: t.offset || 0 }, at)
		}
	})
	tl.to({}, { duration: 0.8 }, at)
}

// ── The script, one builder per step ─────────────────────────────

const OV = 0.55 // pace of the compressed mechanisms in Part I

const build = {
	// ════════ Part I · The big picture ════════

	goal(tl) {
		tl.set('#goal', { opacity: 1 })
		tl.from(['#goal-head', '#goal-diagram', '#goal-hint'], { opacity: 0, duration: 0.8 })
		tl.fromTo('#goal-arrow', { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.6 })
		fadeIn(tl, '#goal-msg')
		tl.to('#goal-msg', { motionPath: { path: '#goal-arrow' }, duration: 1.2, ease: 'power1.inOut' })
		return ['#goal']
	},

	intro(tl) {
		tl.from(['#chainA', '#chainB', '#offchain-band', '#colA', '#colB', '#jam-frame', '#jam'], {
			opacity: 0,
			duration: 0.6,
		})
	},

	anatomy(tl) {
		const row = (k, pos) => {
			tl.to(`#an-id .k-${k}`, { fillOpacity: 1, duration: 0.3 }, pos)
			tl.fromTo(`#an-row-${k}`, { opacity: 0 }, { opacity: 1, duration: 0.35 }, '<')
		}
		tl.fromTo('#anatomy', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		tl.to('#an-id .k-punct', { fillOpacity: 1, duration: 0.3 })
		row('kind', '+=0.2')
		row('rcpt', '+=0.3')
		beat(tl)
		row('dom')
		beat(tl)
		row('num')
		beat(tl)
		tl.fromTo('#an-ack', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		fadeIn(tl, '#an-short', '+=0.3')
		return ['#anatomy']
	},

	'ov-open'(tl) {
		addLeaf(tl, '#a-leaf0')
		fadeIn(tl, '#a-phase-opening', '+=0.1')
		beat(tl)
		drawLine(tl, '#a-fold', 0.5)
		swap(tl, '#a-root-0', '#a-root-1')
		pulse(tl, '#a-root-pill', '<')
		marker(tl, 1, '<')
		archiveSends(tl, 'a', [[0, 174, 138, 266]], OV)
		beat(tl, ['#a-fold'])
		const route = settleRoot(tl, 'A', 'pA', { speed: OV })
		marker(tl, 2, '<')
		return route
	},

	'ov-accept'(tl) {
		fadeIn(tl, '#user')
		tl.set('#tx', { x: 1100, y: 411 })
		travel(tl, '#tx', '#pTx1', 0.7)
		tl.to('#tx', { opacity: 1, duration: 0.3 }, '<')
		flash(tl, '#colB rect')
		travel(tl, '#tx', '#pTx2', 0.5)
		beat(tl, ['#tx', '#user'])
		swap(tl, '#b-empty', '#b-channel', '<')
		addLeaf(tl, '#b-leaf0', '+=0.1')
		fadeIn(tl, '#b-leaf0-detail')
		beat(tl)
		drawLine(tl, '#b-fold', 0.5)
		swap(tl, '#b-root-0', '#b-root-1')
		pulse(tl, '#b-root-pill', '<')
		marker(tl, 1, '<')
		archiveSends(tl, 'b', [[0, 794, 210, 886]], OV)
		beat(tl, ['#b-fold'])
		const route = settleRoot(tl, 'B', 'pB', { speed: OV })
		marker(tl, 2, '<')
		return route
	},

	'ov-read'(tl) {
		pulse(tl, ['#b-ring0', '#b-head'], undefined, 1.25)
		drawLine(tl, '#read-line', 0.7)
		beat(tl)
		exchange(tl, '#req', '#pReq', [530, 399], '#resp', '#pResp', [655, 426], '#colB')
		marker(tl, 3, '<')
		fadeIn(tl, ['#a-fetched', '#fet-a0', '#fet-a0-ok'])
		beat(tl, ['#read-line', '#req', '#resp', '#offchain-band-hi', '#a-fetched', '#fet-a0', '#fet-a0-ok'])
		appear(tl, '#inh', 290, 411)
		travel(tl, '#inh', '#pInh', 0.6)
		marker(tl, 4, '<')
		swap(tl, '#a-phase-opening', '#a-phase-open')
		swap(tl, '#a-ack-none', '#a-ack-reg', '+=0.2')
		beat(tl, ['#inh'])
		marker(tl, 5)
		pulse(tl, '#a-req-line', '<', 1.08)
	},

	'ov-send'(tl) {
		fadeOut(tl, '#a-req-line')
		fadeIn(tl, ['#a-block', '#a-credit'], '<')
		flash(tl, '#colA rect')
		beat(tl)
		fadeIn(tl, '#a-split')
		sendData(tl, 1, 228, 15, 0.7)
		sendData(tl, 2, 282, 22.5, 0.7)
		beat(tl, ['#send-log1', '#send-log2'])
		drawLine(tl, '#a-fold', 0.5)
		swap(tl, '#a-root-1', '#a-root-2')
		pulse(tl, '#a-root-pill', '<')
		marker(tl, 1, '<')
		fadeIn(tl, '#a-digest')
		beat(tl, ['#a-fold'])
		archiveSends(tl, 'a', [[1, 228, 138, 310], [2, 282, 138, 354]], OV)
	},

	'ov-settleN'(tl) {
		const route = settleRoot(tl, 'A', 'pA', { tok: '#tokA2', last: 5, ring: '#a-ring1', headX: 88, speed: OV })
		marker(tl, 2, '<')
		swap(tl, '#a-block', '#a-block-ok')
		return route
	},

	'ov-fetch'(tl) {
		pulse(tl, ['#a-ring1', '#a-head'], undefined, 1.25)
		drawLine(tl, '#read-line2', 0.8)
		beat(tl)
		exchange(tl, '#mreq', '#pMReq', [670, 399], '#mresp', '#pMResp', [545, 426], '#colA')
		marker(tl, 3, '<')
		fadeIn(tl, ['#b-fetched', '#fet-b0', '#fet-b1', '#fet-b2', '#fet-b-ok'])
		return ['#read-line2', '#mreq', '#mresp', '#offchain-band-hi']
	},

	'ov-consume'(tl) {
		fadeIn(tl, '#b-block')
		appear(tl, '#inhB', 910, 411)
		travel(tl, '#inhB', '#pTx2', 0.6)
		fadeOut(tl, ['#b-fetched', '#fet-b0', '#fet-b1', '#fet-b2', '#fet-b-ok'], '<')
		marker(tl, 4, '<')
		beat(tl, ['#inhB'])
		addLeaf(tl, '#b-in0', '<')
		addLeaf(tl, '#b-in1', '-=0.4')
		addLeaf(tl, '#b-in2', '-=0.4')
		swap(tl, '#b-front-0', '#b-front-3')
		beat(tl)
		fadeIn(tl, '#b-record')
	},

	'ov-settleM'(tl) {
		appear(tl, '#wpB', 910, 411)
		travelWithTrail(tl, '#wpB', 'pB2', 0.8)
		flash(tl, '#refine rect')
		travelWithTrail(tl, '#wpB', 'pB3', 0.5)
		flash(tl, '#accumulate rect')
		marker(tl, 4, '<')
		beat(tl, ['#wpB', '#trail-pB2', '#trail-pB3'])
		drawLine(tl, '#check-line', 0.8)
		pulse(tl, '#a-ring1', undefined, 1.3)
		fadeIn(tl, '#check-lbl')
		marker(tl, 5, '<')
		swap(tl, '#b-block', '#b-block-ok', '+=0.2')
		return ['#check-line', '#check-lbl']
	},

	'ov-republish'(tl) {
		fadeOut(tl, '#b-record')
		addLeaf(tl, '#b-leaf1')
		swap(tl, '#b-leaf0-detail', '#b-leaf1-detail')
		beat(tl)
		drawLine(tl, '#b-fold', 0.5)
		swap(tl, '#b-root-1', '#b-root-2')
		pulse(tl, '#b-root-pill', '<')
		marker(tl, 1, '<')
		archiveSends(tl, 'b', [[1, 848, 210, 930]], OV)
		beat(tl, ['#b-fold'])
		const route = settleRoot(tl, 'B', 'pB', { tok: '#tokB2', last: 5, ring: '#b-ring1', headX: 88, speed: OV })
		marker(tl, 2, '<')
		return route
	},

	'ov-credit'(tl) {
		pulse(tl, ['#b-ring1', '#b-head'], undefined, 1.25)
		drawLine(tl, '#read-line3', 0.7)
		exchange(tl, '#req2', '#pReq', [530, 399], '#resp2', '#pResp', [655, 426], '#colB')
		marker(tl, 3, '<')
		fadeIn(tl, ['#a-fetched', '#fet-a1', '#fet-a1-ok'])
		beat(tl, ['#read-line3', '#req2', '#resp2', '#offchain-band-hi', '#a-fetched', '#fet-a1', '#fet-a1-ok'])
		appear(tl, '#inh2', 290, 411)
		travel(tl, '#inh2', '#pInh', 0.6)
		marker(tl, 4, '<')
		swap(tl, ['#a-leaf1', '#a-leaf2'], ['#a-leaf1s', '#a-leaf2s'])
		fadeOut(tl, '#a-split', '<')
		swap(tl, '#a-ack-reg-l1', '#a-ack-reg2')
		tl.to('#a-credit-fill', { attr: { width: 0.01 }, duration: 0.5 })
		swap(tl, '#a-cr-3', '#a-cr-0', '<')
		fadeIn(tl, '#a-req2')
		beat(tl, ['#inh2'])
		fadeOut(tl, ['#arc-a0', '#arc-a1', '#arc-a2'])
		fadeIn(tl, '#arc-a-pruned', '+=0.1')
	},

	'ov-legend'(tl) {
		tl.fromTo(['#legend', '#lg-r0', '#lg-r1', '#lg-r2', '#lg-r3', '#lg-r4'], { opacity: 0 }, { opacity: 1, duration: 0.4 })
		pulse(tl, ['#mk1', '#mk2', '#mk3', '#mk4', '#mk5'], '+=0.2', 1.5)
		return ['#legend']
	},

	// ════════ Part II · Under the hood, on block N's messages ════════

	'p2-rewind'(tl) {
		restore(tl, 'ov-read')
		fadeIn(tl, '#rw1')
		return ['#rw1']
	},

	// ① Commit

	's1-intro'(tl) {
		marker(tl, 1)
		fadeOut(tl, '#a-req-line', '<') // consumption records are per block
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
		tl.fromTo('#mmr-l1', { opacity: 0 }, { opacity: 1, duration: 0.4 }, '+=0.3')
		tl.fromTo(['#mmr-e0', '#mmr-e1'], { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.4 })
		fadeIn(tl, '#mmr-n01', '-=0.1')
		tl.fromTo('#mmr-l2', { opacity: 0 }, { opacity: 1, duration: 0.4 }, '+=0.3')
		fadeIn(tl, '#mmr-peaks', '+=0.2')
		pulse(tl, ['#mmr-n01', '#mmr-l2'], '<')
		tl.fromTo(['#mmr-b0', '#mmr-b1'], { drawSVG: '0%' }, { drawSVG: '100%', duration: 0.5 }, '+=0.2')
		fadeIn(tl, '#mmr-root')
		pulse(tl, '#mmr-root', undefined, 1.08)
	},

	's1-fold'(tl) {
		fadeIn(tl, '#bag-right')
		appear(tl, '#bag-fly', 320, 393, '+=0.2')
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

	// ② Settle

	's2-package'(tl) {
		marker(tl, 2)
		flash(tl, '#colA rect', '<')
		appear(tl, '#wp', 290, 411)
		travelWithTrail(tl, '#wp', 'pA2', 1.2)
		flash(tl, '#refine rect')
		fadeOut(tl, '#wp')
		fadeIn(tl, '#refine-wp', '<')
		return ['#trail-pA2']
	},

	's2-refine'(tl) {
		const rows = [0, 1, 2, 3, 4, 5, 6, 7].map((i) => `#rf-r${i}`)
		tl.fromTo(['#rf-card', ...rows, '#rf-foot'], { opacity: 0 }, { opacity: 1, duration: 0.4 })
		pulse(tl, '#rf-r6', '+=0.3', 1.03)
		return ['#rf-card']
	},

	's2-join'(tl) {
		fadeOut(tl, '#refine-wp')
		appear(tl, '#dg', 580, 584)
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
			tl.fromTo(`#ac-r${i}`, { opacity: 0 }, { opacity: 1, duration: 0.3 }, '+=0.2')
		}
		pulse(tl, '#ac-r5', undefined, 1.03)
		fadeIn(tl, '#ac-foot', '+=0.2')
		return ['#ac-card']
	},

	's2-enact'(tl) {
		fadeOut(tl, '#acc-digest')
		appear(tl, '#tokA2', 580, 684)
		travelWithTrail(tl, '#tokA2', 'pA5', 1.0)
		fadeOut(tl, '#tokA2')
		fadeIn(tl, '#a-ring1', '<')
		pulse(tl, '#a-ring1', '<', 1.25)
		tl.to('#a-head', { x: 88, duration: 0.5 })
		swap(tl, '#a-block', '#a-block-ok')
		pulse(tl, '#a-block-ok', '<')
		return ['#trail-pA5']
	},

	// ③ Fetch & verify

	's3-notice'(tl) {
		marker(tl, 3)
		pulse(tl, ['#a-ring1', '#a-head'], '<', 1.25)
		drawLine(tl, '#read-line2', 1)
		flash(tl, '#colB rect')
	},

	's3-fetch'(tl) {
		exchange(tl, '#mreq', '#pMReq', [670, 399], '#mresp', '#pMResp', [545, 426], '#colA')
		pulse(tl, ['#arc-a0', '#arc-a1', '#arc-a2'], '-=1.2', 1.2) // served from the archive
		flash(tl, '#colB rect')
		fadeIn(tl, ['#b-fetched', '#fet-b0', '#fet-b1', '#fet-b2'], '<')
		return ['#mreq', '#mresp', '#offchain-band-hi', '#read-line2']
	},

	's3-verify'(tl) {
		tl.fromTo('#vf-card', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		for (let i = 0; i <= 3; i++) {
			tl.fromTo(`#vf-r${i}`, { opacity: 0 }, { opacity: 1, duration: 0.3 }, '+=0.25')
		}
		pulse(tl, '#vf-r3', undefined, 1.03)
		fadeIn(tl, '#vf-foot', '+=0.2')
		fadeIn(tl, '#fet-b-ok', '<') // the staged payloads are now trusted
		return ['#vf-card']
	},

	// ④ Consume & lift

	's4-inherent'(tl) {
		marker(tl, 4)
		fadeIn(tl, '#b-block', '<')
		flash(tl, '#colB rect')
		appear(tl, '#inhB', 910, 411)
		travel(tl, '#inhB', '#pTx2', 0.8)
		fadeOut(tl, ['#b-fetched', '#fet-b0', '#fet-b1', '#fet-b2', '#fet-b-ok'], '<')
		return ['#inhB']
	},

	's4-consume'(tl) {
		flash(tl, '#chainB .box')
		addLeaf(tl, '#b-in0', '+=0.1')
		addLeaf(tl, '#b-in1', '-=0.3')
		addLeaf(tl, '#b-in2', '-=0.3')
		swap(tl, '#b-front-0', '#b-front-3')
		fadeIn(tl, '#b-record', '+=0.3')
	},

	's5-package'(tl) {
		flash(tl, '#colB rect')
		appear(tl, '#wpB', 910, 411)
		travelWithTrail(tl, '#wpB', 'pB2', 1.2)
		flash(tl, '#refine rect')
		fadeOut(tl, '#wpB')
		fadeIn(tl, '#refine-wpB', '<')
		return ['#trail-pB2']
	},

	's5-refine'(tl) {
		tl.fromTo('#rf2-card', { opacity: 0 }, { opacity: 1, duration: 0.4 })
		for (let i = 0; i <= 5; i++) {
			tl.fromTo(`#rf2-r${i}`, { opacity: 0 }, { opacity: 1, duration: 0.3 }, '+=0.25')
		}
		pulse(tl, '#rf2-r4', undefined, 1.03)
		fadeIn(tl, '#rf2-foot', '+=0.2')
		return ['#rf2-card']
	},

	// ⑤ Settlement check

	's5-settle'(tl) {
		marker(tl, 5)
		fadeOut(tl, '#refine-wpB', '<')
		appear(tl, '#dgB', 580, 584)
		travelWithTrail(tl, '#dgB', 'pB3', 1.0)
		flash(tl, '#accumulate rect')
		fadeOut(tl, '#dgB')
		fadeIn(tl, '#acc-digestB', '<')
		drawLine(tl, '#check-line', 1, '+=0.2')
		pulse(tl, '#a-ring1', undefined, 1.3)
		fadeIn(tl, '#check-lbl')
		swap(tl, '#b-block', '#b-block-ok', '+=0.3')
		pulse(tl, '#b-block-ok', '<')
		return ['#trail-pB3', '#acc-digestB', '#check-line', '#check-lbl']
	},

	'p2-summary'(tl) {
		pulse(tl, ['#mk1', '#mk2', '#mk3', '#mk4', '#mk5'], undefined, 1.5)
		pulse(tl, ['#a-ring1', '#b-ring0'], '+=0.1', 1.25)
	},
}

const tl = gsap.timeline({ paused: true })
const marks = {} // step id → beat boundaries inside the step
let leftovers = []
let prevId = null
for (const s of steps) {
	tl.addLabel(s.id)
	if (leftovers.length) fadeOut(tl, leftovers)
	if (prevId) clean[prevId] = tl.duration()
	beatMarks = []
	leftovers = build[s.id](tl) ?? []
	marks[s.id] = beatMarks
	tl.to({}, { duration: 0.15 }) // breathing room before the step ends
	prevId = s.id
}

const starts = steps.map((s) => tl.labels[s.id])
// End a hair before the next label: seeking exactly onto it would already
// fire the next step's zero-length sets.
const ends = steps.map((_, i) => (starts[i + 1] ?? tl.duration() + 1e-3) - 1e-3)

// Beat k of step i plays from bounds[i][k] to just before bounds[i][k + 1].
const bounds = steps.map((s, i) => [starts[i], ...marks[s.id], ends[i] + 1e-3])
const beatCount = (i) => bounds[i].length - 1
const beatStart = (i, k) => bounds[i][k]
const beatEnd = (i, k) => bounds[i][k + 1] - 1e-3

// ── Navigation ──────────────────────────────────────────────────

const $ = (id) => document.getElementById(id)
const stageNames = [...new Set(steps.map((s) => s.stage))]
const stageFirst = stageNames.map((n) => steps.findIndex((s) => s.stage === n))
const stageBtns = stageNames.map((name, k) => {
	const b = document.createElement('button')
	b.textContent = chips[name]
	b.title = name
	b.addEventListener('click', () => go(stageFirst[k], true))
	$('stages').append(b)
	return b
})
const dots = steps.map((s, i) => {
	const b = document.createElement('button')
	b.title = s.title.replace(/<[^>]+>/g, '')
	b.addEventListener('click', () => go(i, true))
	$('dots').append(b)
	return b
})

let cur = 0
let beatIdx = 0
let playing = null

function render() {
	const s = steps[cur]
	const k = stageNames.indexOf(s.stage)
	const inStage = steps.filter((t) => t.stage === s.stage).length
	const n = beatCount(cur)
	$('stage').textContent = `${s.stage} · step ${cur - stageFirst[k] + 1}/${inStage}`
		+ (n > 1 ? ` · ${beatIdx + 1}/${n}` : '')
	stageBtns.forEach((b, j) => {
		b.classList.toggle('current', j === k)
		b.classList.toggle('done', j < k)
	})
	$('step-title').innerHTML = s.title
	$('step-body').innerHTML = s.body
	// One bullet per beat: earlier ones stay, the current one is highlighted,
	// later ones appear when their beat plays.
	if (n > 1) {
		$('step-body').querySelectorAll('li').forEach((li, j) => {
			li.classList.toggle('past', j < beatIdx)
			li.classList.toggle('now', j === beatIdx)
			li.classList.toggle('later', j > beatIdx && beatIdx < n - 1)
		})
	}
	$('step-ref').innerHTML = s.ref ? `Spec: ${s.ref}` : ''
	dots.forEach((d, i) => {
		d.classList.toggle('done', i < cur)
		d.classList.toggle('current', i === cur)
		d.classList.toggle('other-stage', steps[i].stage !== s.stage)
	})
	$('prev').disabled = cur === 0 && beatIdx === 0
	$('next').disabled = cur === steps.length - 1 && beatIdx === n - 1
	history.replaceState(null, '', `#${cur}`)
}

// Play beat k of step i from its start, or show its end state.
function show(i, k, animate) {
	playing?.kill()
	playing = null
	cur = i
	beatIdx = k
	render()
	if (animate) {
		tl.seek(beatStart(i, k))
		playing = tl.tweenFromTo(beatStart(i, k), beatEnd(i, k), { ease: 'none' })
	} else {
		tl.seek(beatEnd(i, k))
	}
}

// Whole steps: animate from the first beat, or jump to the finished step.
const go = (i, animate) => (animate ? show(i, 0, true) : show(i, beatCount(i) - 1, false))

function next() {
	if (playing?.isActive()) return show(cur, beatIdx, false) // first press skips the animation
	if (beatIdx < beatCount(cur) - 1) show(cur, beatIdx + 1, true)
	else if (cur < steps.length - 1) show(cur + 1, 0, true)
}

function prev() {
	if (beatIdx > 0) show(cur, beatIdx - 1, false)
	else if (cur > 0) go(cur - 1, false)
}

$('next').addEventListener('click', next)
$('prev').addEventListener('click', prev)
$('replay').addEventListener('click', () => show(cur, beatIdx, true))

document.addEventListener('keydown', (e) => {
	if (['ArrowRight', ' ', 'PageDown', 'Enter'].includes(e.key)) next()
	else if (['ArrowLeft', 'PageUp', 'Backspace'].includes(e.key)) prev()
	else if (e.key === 'r' || e.key === 'R') show(cur, beatIdx, true)
	else if (e.key === 'Home') go(0, true)
	else return
	e.preventDefault()
})

// Deep links (#3) land on the finished state of that step.
const initial = Number.parseInt(location.hash.slice(1), 10)
if (initial > 0 && initial < steps.length) go(initial, false)
else go(0, true)

// Hook for the screenshot script.
window.__deck = { go, show, beatCount, steps, tl, starts, ends }
