// Narration for each step. `id` doubles as the timeline label in main.js.
// Refs: SM = speculative-messaging-design.md, PS = parachain-service-on-jam.md.
// The scene shows *what* changes; the panel explains *why*.
//
// One pass through the round trip. Channel setup is told compactly; the first
// data block (block N) then shows every mechanism in detail on its way to B.

const S0 = 'Introduction'
const S1 = 'Opening the channel'
const S2 = 'A sends block N'
const S3 = 'Block N settles on JAM'
const S4 = 'B fetches the messages'
const S5 = 'B consumes them'
const S6 = 'Block M settles'
const S7 = 'Credit flows back'

// Labels of the chapter buttons in the panel.
export const chips = { [S0]: '★', [S1]: '1', [S2]: '2', [S3]: '3', [S4]: '4', [S5]: '5', [S6]: '6', [S7]: '7' }

export const steps = [
	// ── Introduction ──
	{
		id: 'goal',
		stage: S0,
		title: 'Messages between two parachains',
		body: `
			<p><strong>Goal:</strong> parachain A sends messages to parachain B.</p>
			<ul>
				<li>Think of it as the successor of HRMP, except that messages never pass
				through the relay chain (here: JAM). The chains exchange them directly; JAM only
				settles 32-byte roots that commit to them.</li>
				<li>Messages travel over a <strong>channel</strong>. A→B lets A write and B read.</li>
				<li>Channels are unidirectional: replies would need a second channel B→A.</li>
				<li>The walkthrough follows the <strong>inclusion tier</strong>: B consumes only
				what JAM has already settled for A.</li>
			</ul>`,
		ref: 'SM (speculative-messaging-design.md) · PS (parachain-service-on-jam.md)',
	},
	{
		id: 'intro',
		stage: S0,
		title: 'The cast',
		body: `
			<ul>
				<li><strong>Parachains A and B</strong>: their runtimes keep the message
				streams. A channel is a pair of streams: <em>data</em> (A writes, B reads)
				and <em>ack</em> (B writes, A reads).</li>
				<li><strong>Collators</strong> build blocks as today, and talk to each other
				directly to move messages.</li>
				<li><strong>JAM's Parachain Service</strong> takes over from the relay chain.
				Refine plays the role of backing (runs the validation code on the PoV),
				Accumulate the role of inclusion (enacts the candidate). Per parachain it keeps
				a small <em>settlement ring</em> of recent roots.</li>
			</ul>`,
		ref: 'PS §2 (architecture), §8 (messaging)',
	},
	{
		id: 'anatomy',
		stage: S0,
		title: 'Reading a stream id',
		body: `
			<ul>
				<li>The recipient field always names who <em>reads</em> the stream.</li>
				<li><code>domain</code> is reserved address space for apps. Until a chain
				delegates it, everything runs at 0.</li>
				<li><code>num</code> numbers channels between the same pair, so A can run
				several independent channels to B.</li>
				<li>B answers on the mirrored id: same domain and num, kind flipped,
				recipient swapped.</li>
			</ul>
			<p>On screen this pair is <em>Channel A→B</em>, with its streams labelled
			data and ack.</p>`,
		ref: 'SM :330 (StreamId), :338 (reserved domain), :1672 (Channels)',
	},
	// ── Opening the channel ──
	{
		id: 'ov-open',
		stage: S1,
		title: 'A opens the channel',
		body: `
			<ul>
				<li><code>OpenChannel</code> becomes leaf #0 of A's data stream, the only message A
				may send without credit. The channel is <em>Opening</em>.</li>
				<li>A's block commits to all its streams with one hash, the new
				<code>StreamsRoot</code> T<sub>A1</sub> (what the UMP <code>Provides</code> signal
				carried on the relay chain). A's collator archives the payload.</li>
				<li>The block goes through JAM, and T<sub>A1</sub> lands in A's settlement
				ring. How a root is built and settled is shown in detail with A's first data
				block, further on.</li>
			</ul>`,
		ref: 'SM :1748 (Opening), :549 (commitments); PS host fn 204 (:802)',
	},
	{
		id: 'ov-accept',
		stage: S1,
		title: 'B accepts and grants credit',
		body: `
			<ul>
				<li>Someone on B submits <code>accept_open_channel(A, 0, 0)</code>, a signed
				extrinsic like <code>hrmp_accept_open_channel</code>, through B's collator.</li>
				<li>B records the channel and appends a <code>Register</code> to its ack stream:
				the watermark <code>up_to</code> and a credit grant for A.</li>
				<li>That leaf is a send, so B commits T<sub>B1</sub>; B's collator archives it.</li>
				<li>T<sub>B1</sub> settles in B's ring.</li>
			</ul>`,
		ref: 'SM :1758 (accept), :1885 (Register)',
	},
	{
		id: 'ov-read',
		stage: S1,
		title: 'A reads the register; the channel is open',
		body: `
			<ul>
				<li>A's collator watches B's ring. It moved: the newest root is T<sub>B1</sub>.</li>
				<li>It fetches the head of B's ack stream, proven against T<sub>B1</sub>. The ack
				stream is latest-wins: only the newest register counts, so A reads one leaf with an
				inclusion proof.</li>
				<li>The register enters A's next block through the messaging inherent. The
				channel is open and A holds credit.</li>
				<li>That block now depends on T<sub>B1</sub>: JAM enacts it only if
				T<sub>B1</sub> is in B's ring. Since T<sub>B1</sub> is already settled, this
				carries no risk from B's side. B's block M passes the same check later on.</li>
			</ul>`,
		ref: 'SM :1952 (reading the register)',
	},
	// ── A sends block N ──
	{
		id: 's1-intro',
		stage: S2,
		title: "A's collator starts block N",
		body: `
			<ul>
				<li>Consumption records are per block. The previous block's
				<code>requires (B, T<sub>B1</sub>)</code> belonged to that block, so block N
				starts without it.</li>
				<li>The register gives A credit. In flight is everything on the data stream
				at positions ≥ <code>up_to</code>, signals included: so far only
				<code>OpenChannel</code>, 1 of 16 messages. Bytes are counted the same way.</li>
			</ul>`,
		ref: 'SM :1937 (window accounting)',
	},
	{
		id: 's1-send',
		stage: S2,
		title: 'Two sends, each gated by credit',
		body: `
			<ul>
				<li>The app calls <code>send(B, 0, 0, data)</code>. The pallet checks in-flight
				&lt; grant, wraps the bytes as <code>Data</code> and host-appends them to
				<code>OutboundMessages</code>, which holds this block's sends only.</li>
				<li>Positions are derived, never stored: frontier <code>leaf_count</code> plus
				the index in this block, so #1 and #2.</li>
				<li>The stored frontier is untouched during the block; it still covers only #0.</li>
			</ul>`,
		ref: 'SM :1593 (send), :659–673 (OutboundFrontier, OutboundMessages)',
	},
	{
		id: 's1-bag',
		stage: S2,
		title: 'Block end: bag the data stream',
		body: `
			<ul>
				<li>Each stream is a Merkle Mountain Range. In memory, the runtime appends this
				block's leaves to the frontier: #1 merges with #0 into a peak, #2 starts a new one.</li>
				<li>Bagging the peaks gives the data stream's MMR root. No stream root is stored
				anywhere; it is always recomputed from the frontier.</li>
			</ul>`,
		ref: 'SM :197 (MMR), :640 (MmrFrontier), :694 (sender lifecycle)',
	},
	{
		id: 's1-fold',
		stage: S2,
		title: 'Fold into one StreamsRoot',
		body: `
			<ul>
				<li>The commitment trie is keyed by stream id and its leaves are stream roots.
				Only the paths of touched streams are rehashed.</li>
				<li>The new root T<sub>A2</sub> is the one hash A publishes for block N, in two
				forms: a header digest for off-chain verifiers, and the root its validation
				code declares to JAM via host fn 204.</li>
				<li>A block that touches no stream publishes nothing.</li>
			</ul>`,
		ref: 'SM :422 (commitment tree), :2573 (header digest); PS :802',
	},
	{
		id: 's1-outputs',
		stage: S2,
		title: 'What leaves the block',
		body: `
			<ul>
				<li>T<sub>A2</sub> is deposited as A's header digest
				(<code>DigestItem::Consensus</code>, at most one per header).</li>
				<li>A's collator pulls the block's sends through the runtime API
				<code>outbound_messages()</code> into its archive at #1 and #2. Collators never
				read messaging storage directly.</li>
				<li>The archive is node-local disk, not chain state: the runtime keeps only the
				frontier. At block N+1 init the frontier absorbs #1 and #2.</li>
			</ul>`,
		ref: 'SM :728 (runtime API), :2039 (archive), :2573',
	},
	// ── Block N settles on JAM ──
	{
		id: 's2-package',
		stage: S3,
		title: 'A work package for block N',
		body: `
			<ul>
				<li>A's collator wraps block N into a work package for the Parachain Service:
				one work item whose payload names the validation code hash, with the PoV as the
				item's extrinsic.</li>
				<li>The package carries an auth token for the core's authorizer. The authorizer
				config, pinned by the Coretime chain, says which para the item belongs to.</li>
				<li>Guarantors assigned to the core pick it up and run Refine.</li>
			</ul>`,
		ref: 'PS §3.2 (work items), §7.1 (authorizer)',
	},
	{
		id: 's2-refine',
		stage: S3,
		title: 'Refine re-executes block N',
		body: `
			<ul>
				<li>Refine is the backing step: it fetches the validation code by hash and runs
				<code>jam_validate_block</code> in a child PVM on the PoV.</li>
				<li>The validation code reports through host calls. 200 and 201 are mandatory;
				204 declares T<sub>A2</sub>, the same root block N put in its header digest.</li>
				<li>205 is not called: block N consumed nothing, so it depends on no other chain.</li>
			</ul>`,
		ref: 'PS §4.1, §4.3 (host fns 200–205), §3.3 (work digest)',
	},
	{
		id: 's2-join',
		stage: S3,
		title: 'Guaranteed and available',
		body: `
			<ul>
				<li>The work report goes on-chain. JAM validators guarantee it, and the work
				package's data is made available by erasure coding.</li>
				<li>Only then does JAM hand the digest to the service's Accumulate.</li>
			</ul>`,
		ref: 'PS §2 (CRJA pipeline)',
	},
	{
		id: 's2-accumulate',
		stage: S3,
		title: 'Accumulate checks, then enacts',
		body: `
			<ul>
				<li>Accumulate is the inclusion step, the counterpart of
				<code>enact_candidate</code>. Each report pays for itself: the gas gate skips any
				report whose own gas limit cannot cover it.</li>
				<li>Checks 1–4 make sure block N extends A's current head with A's current code.</li>
				<li>Check 5 is the messaging check. Block N requires nothing, so it passes
				trivially; B's block M will be checked here for real.</li>
			</ul>`,
		ref: 'PS §5.1 (per-work-package work)',
	},
	{
		id: 's2-enact',
		stage: S3,
		title: "T<sub>A2</sub> lands in A's ring",
		body: `
			<ul>
				<li>Enactment writes block N's head data and pushes T<sub>A2</sub> at the ring's
				head. The head moves on to the next free slot.</li>
				<li>The ring keeps the last 64 roots. Accumulate also returns a Merkle root over
				the heads it changed: JAM's commitment to the new head of A.</li>
			</ul>`,
		ref: 'PS §5.1 step 6, §5.5 (head commitment), §8.1 (settlement ring)',
	},
	// ── B fetches the messages ──
	{
		id: 's3-notice',
		stage: S4,
		title: "B's collator sees T<sub>A2</sub> in A's ring",
		body: `
			<ul>
				<li>B's collator watches A's ring head every JAM block. It advanced, and the
				newest root behind it is T<sub>A2</sub>.</li>
				<li><code>consumed_streams()</code> tells it what to fetch: A's data stream to B,
				from position #0. B has not consumed anything yet, not even
				<code>OpenChannel</code>.</li>
				<li>Inclusion tier: the target is the newest root <em>settled</em> on JAM,
				so whatever B builds on it carries no risk from A's side.</li>
			</ul>`,
		ref: 'SM :740 (consumed_streams), :950 (root choice)',
	},
	{
		id: 's3-fetch',
		stage: S4,
		title: 'Fetch by position, trust by root',
		body: `
			<ul>
				<li><code>MessagesRequest{stream: Channel{B,0,0}, start: 0, under: T<sub>A2</sub>,
				max_bytes}</code> goes to A's collators.</li>
				<li>A's collator answers from its archive: payloads #0–#2 (OpenCh, m<sub>1</sub>,
				m<sub>2</sub>), an extension proof and a tree proof that tie them to T<sub>A2</sub>.</li>
				<li>Addressing is by stream and position, never by block: B never has to look
				for which of A's blocks wrote to its stream.</li>
			</ul>
			<p class="key"><strong>The key split.</strong> On-chain, the Parachain Service only
			stores 32-byte roots, one per enacted block. The messages themselves and the
			proofs that tie them to a root travel collator to collator, off-chain. That is
			what keeps settlement cheap.</p>`,
		ref: 'SM :820 (fetch protocol)',
	},
	{
		id: 's3-verify',
		stage: S4,
		title: 'B verifies before it trusts anything',
		body: `
			<ul>
				<li>Recompute: hash the payloads into leaves and append them to the tracked
				frontier. Order and count need no separate check; anything else gives a
				different root.</li>
				<li>The extension is empty because the payloads reach the stream's entry under
				T<sub>A2</sub>: B is caught up. The tree proof then yields A's StreamsRoot.</li>
				<li>It equals T<sub>A2</sub>, a root B read from JAM itself, so the whole
				response is authentic.</li>
			</ul>`,
		ref: 'SM :936 (verification)',
	},
	// ── B consumes them ──
	{
		id: 's4-inherent',
		stage: S5,
		title: "B's collator starts block M",
		body: `
			<ul>
				<li>The verified payloads go into block M's messaging inherent, like the register
				went into A's block during setup.</li>
				<li>The inherent carries payloads only, never a StreamsRoot. A root chosen by
				the block author would prove nothing to the runtime.</li>
			</ul>`,
		ref: 'SM :800 (inherent), :936',
	},
	{
		id: 's4-consume',
		stage: S5,
		title: 'B consumes #0–#2',
		body: `
			<ul>
				<li>B's runtime hashes each payload into its leaf and appends it to
				<code>InboundFrontier</code> for A's data stream: leaf count 0 → 3. That
				recomputation is the runtime's only check.</li>
				<li><code>OpenChannel</code> is consumed in order like any message; m<sub>1</sub>
				and m<sub>2</sub> are handed to B's application.</li>
				<li>The block writes a consumption record: for A's data stream, where consumption
				started and where it ended. It names no root. B sent nothing, so B's
				StreamsRoot stays T<sub>B1</sub>.</li>
			</ul>`,
		ref: 'SM :676 (InboundFrontier), :1244 (consumption record)',
	},
	{
		id: 's5-package',
		stage: S5,
		title: 'Block M goes to JAM, with a lift',
		body: `
			<ul>
				<li>B's collator builds the work package as A's did. The PoV additionally
				carries one <em>lift</em> per consumed stream, grouped by source.</li>
				<li>Here the lift is just a tree proof (about 300 B): B is caught up, so no
				extension is needed.</li>
			</ul>`,
		ref: 'SM :1177 (requires lifting)',
	},
	{
		id: 's5-refine',
		stage: S5,
		title: 'The wrapper turns consumption into a requirement',
		body: `
			<ul>
				<li>After executing block M, the <code>validate_block</code> wrapper reads the
				consumption record and stitches the intervals of all blocks in the candidate.
				One block, one interval: the endpoint is frontier(3).</li>
				<li>The lift carries the endpoint to a committed root: extension (empty) to the
				stream root, tree proof to A's StreamsRoot T<sub>A2</sub>.</li>
				<li>Host fn 205 declares <code>[(A, T<sub>A2</sub>)]</code>, the old UMP
				<code>Requires</code>. The service's Refine only checks the shape (at most 32
				sources, no duplicates, not itself); proving the lift is the parachain's own code.</li>
			</ul>`,
		ref: 'SM :1330 (build_requires); PS host fn 205 (:803)',
	},
	// ── Block M settles ──
	{
		id: 's5-settle',
		stage: S6,
		title: "Check 5: is T<sub>A2</sub> in A's ring?",
		body: `
			<ul>
				<li>Accumulate looks up <code>(A, T<sub>A2</sub>)</code> in
				<code>messages_member</code>. It is there, so block M is enacted: B's head
				moves to M.</li>
				<li>Had the root been missing, B's candidate would be rejected silently: no head
				write, no log entry, all its upward messages dropped.</li>
				<li>There is no virtual window on JAM: a requirement only matches roots already
				in the ring when this package is accumulated.</li>
			</ul>`,
		ref: 'PS §5.1 step 5, §8.1 (checking membership)',
	},
	// ── Credit flows back ──
	{
		id: 'ov-republish',
		stage: S7,
		title: 'B confirms with a new register',
		body: `
			<ul>
				<li>Once consumption has advanced far enough (e.g. a quarter of the window) or an
				age threshold passes, B appends a new <code>Register</code> with
				<code>up_to 3</code>: everything before #3 is consumed.</li>
				<li>That is a send: B commits T<sub>B2</sub> and archives the leaf.</li>
				<li>T<sub>B2</sub> settles in B's ring.</li>
			</ul>`,
		ref: 'SM :1942 (publishing)',
	},
	{
		id: 'ov-credit',
		stage: S7,
		title: 'Credit flows back to A',
		body: `
			<ul>
				<li>A's collator reads the new register, proven against T<sub>B2</sub>.</li>
				<li>A's next block imports it. In flight counts positions ≥ <code>up_to</code>,
				so nothing is in flight any more: full credit again.</li>
				<li>A may prune the archived payloads #0–#2 once that register is irreversible.
				Read under a settled root, it is.</li>
			</ul>`,
		ref: 'SM :1937 (window accounting), :2039 (pruning)',
	},
	{
		id: 'summary',
		stage: S7,
		title: 'The whole picture',
		body: `
			<ul>
				<li>A sent m<sub>1</sub> and m<sub>2</sub>; B consumed them; B's register gave the
				credit back; A pruned what it no longer needs.</li>
				<li>The register travelled the other way through the same machinery: A fetched and
				verified it, consumed it through an inherent, and A's block passed the settlement
				check against T<sub>B1</sub> in B's ring.</li>
				<li>On JAM: a few 32-byte roots per ring and a membership check per dependency.
				Every payload and proof stayed with the two chains.</li>
			</ul>`,
		ref: '',
	},
]
