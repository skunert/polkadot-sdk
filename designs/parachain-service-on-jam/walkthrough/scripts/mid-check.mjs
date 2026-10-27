import { chromium } from 'playwright'
const [url, out] = process.argv.slice(2)
const b = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined })
const p = await b.newPage({ viewport: { width: 1600, height: 900 } })
await p.goto(url); await p.waitForFunction(() => window.__deck)
// Sample the token's position across the collator hop of step 3 (index 2).
const ys = await p.evaluate(() => {
	const d = window.__deck, i = d.steps.findIndex((s) => s.id === 'ov-open'), out = []
	d.go(i, false)
	for (let t = d.starts[i]; t < d.ends[i]; t += 0.05) {
		d.tl.seek(t)
		const m = document.getElementById('tokA').transform.baseVal.consolidate()?.matrix
		if (m) out.push([+t.toFixed(2), Math.round(m.e), Math.round(m.f)])
	}
	return out
})
for (let k = 1; k < ys.length; k++) { const j = Math.hypot(ys[k][1]-ys[k-1][1], ys[k][2]-ys[k-1][2]); if (j > 30) console.log('jump', String(ys[k-1]), '->', String(ys[k])) }
let maxJump = 0
for (let k = 1; k < ys.length; k++) maxJump = Math.max(maxJump, Math.hypot(ys[k][1]-ys[k-1][1], ys[k][2]-ys[k-1][2]))
console.log('samples', ys.length, 'max step between 50ms samples:', maxJump.toFixed(1), 'px')
console.log(ys.filter(([, x, y]) => y > 340 && y < 450).slice(0, 12).map(String).join(' | '))
await p.evaluate(() => { const d = window.__deck; const i = d.steps.findIndex((s) => s.id === 'ov-open'); d.go(i, false); d.tl.seek(d.starts[i] + 1.75) })
await p.screenshot({ path: `${out}/mid-collator.png` })
await b.close()
