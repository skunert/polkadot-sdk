// Usage: node scripts/shoot.mjs <url> <outdir>
// Screenshots the end state of every step, plus mid-animation frames.
import { chromium } from 'playwright'

const [url, out] = process.argv.slice(2)
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined })
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } })
const errors = []
page.on('pageerror', (e) => errors.push(String(e)))
page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))
await page.goto(url)
await page.waitForFunction(() => window.__deck)
const n = await page.evaluate(() => window.__deck.steps.length)
for (let i = 0; i < n; i++) {
	await page.evaluate((i) => window.__deck.go(i, false), i)
	await page.screenshot({ path: `${out}/step-${i}.png` })
}
// Mid-flight frames: fraction through a step's segment, addressed by step id.
const mids = [['anatomy', 0.5], ['ov-read', 0.7], ['s3-fetch', 0.6], ['s5-settle', 0.75]]
for (const [id, f] of mids) {
	const i = await page.evaluate(([id, f]) => {
		const d = window.__deck
		const i = d.steps.findIndex((s) => s.id === id)
		d.go(i, false)
		d.tl.seek(d.starts[i] + (d.ends[i] - d.starts[i]) * f)
		return i
	}, [id, f])
	await page.screenshot({ path: `${out}/mid-${i}-${id}-${f}.png` })
}
// Real keyboard flow from the start.
await page.goto(url.split('#')[0] + '#0')
await page.reload()
await page.keyboard.press('ArrowRight')
await page.waitForTimeout(4000)
await page.keyboard.press('ArrowRight')
await page.waitForTimeout(200)
await page.keyboard.press('ArrowRight') // skip-to-end press
const state = await page.evaluate(() => location.hash)
console.log('after keys:', state)
console.log('errors:', errors.length ? errors : 'none')
await browser.close()
