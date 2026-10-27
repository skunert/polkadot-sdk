// Narration for each step. `id` doubles as the timeline label in main.js.
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
				<li>This replaces HRMP. Unlike HRMP, the messages never pass through the relay chain, or here
				JAM: the two chains exchange them directly, and JAM only stores 32-byte hashes (roots)
				that commit to them.</li>
				<li>Messages travel over a <strong>channel</strong> from A to B. Channels are one-way: for
				replies, B would open its own channel to A.</li>
				<li>B only consumes messages whose root JAM has already accepted. The design calls this the
				<strong>inclusion tier</strong>; faster tiers exist but are not shown here.</li>
			</ul>`,
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
	},
	{
		id: 'anatomy',
		stage: S0,
		title: 'Reading a stream id',
		body: `
			<ul>
				<li>The recipient field always names who <em>reads</em> the stream.</li>
				<li><code>domain</code> is reserved address space for apps. Until a chain hands it out,
				everything uses 0.</li>
				<li><code>num</code> numbers channels between the same pair, so A can run several
				independent channels to B.</li>
				<li>B's stream for this channel uses the mirrored id: kind <code>Ack</code>, recipient A,
				same domain and num.</li>
			</ul>
			<p>On screen this pair is <em>Channel A→B</em>, with its streams labelled
			data and ack.</p>`,
	},
	// ── Opening the channel ──
	{
		id: 'ov-open',
		stage: S1,
		title: 'A opens the channel',
		body: `
			<ul>
				<li><code>OpenChannel</code> becomes message #0 of A's data stream. It is the only message A
				may send before B grants any credit (permission to send). The channel is <em>Opening</em>.</li>
				<li>At the end of the block, A combines all its streams into one hash, its
				<code>StreamsRoot</code>, here T<sub>A1</sub>. A's collator keeps a copy of the message in its
				archive.</li>
				<li>The block goes through JAM, and T<sub>A1</sub> is stored in A's settlement ring. Both steps
				are shown in detail later, with A's first data block.</li>
			</ul>`,
	},
	{
		id: 'ov-accept',
		stage: S1,
		title: 'B accepts and grants credit',
		body: `
			<ul>
				<li>Someone on B submits <code>accept_open_channel(A, 0, 0)</code>, a signed extrinsic like
				<code>hrmp_accept_open_channel</code>. B's collator includes it in B's next block.</li>
				<li>B records the channel and appends a <code>Register</code> to its ack stream. The register
				says how much A may send (the credit) and how far B has read (<code>up_to</code>).</li>
				<li>B's streams changed, so B's block commits a new root T<sub>B1</sub>. B's collator archives the
				register.</li>
				<li>T<sub>B1</sub> is stored in B's settlement ring.</li>
			</ul>`,
	},
	{
		id: 'ov-read',
		stage: S1,
		title: 'A reads the register; the channel is open',
		body: `
			<ul>
				<li>A's collator watches B's ring on JAM. It changed: B's newest root is T<sub>B1</sub>.</li>
				<li>A's collator asks B's collators for the newest register and checks it against T<sub>B1</sub>
				with a Merkle proof. Only the newest register matters, so one entry is enough.</li>
				<li>The register goes into A's next block through the messaging inherent. The channel is open
				and A has credit.</li>
				<li>Reading it makes A's block depend on T<sub>B1</sub>: JAM accepts the block only if T<sub>B1</sub> is
				in B's ring. It already is, so this cannot fail because of B. The same check is shown in
				detail for B's block M.</li>
			</ul>`,
	},
	// ── A sends block N ──
	{
		id: 's1-intro',
		stage: S2,
		title: "A's collator starts block N",
		body: `
			<ul>
				<li>A's collator starts block N. The dependency on T<sub>B1</sub> belonged to the previous block;
				every block declares its own.</li>
				<li>A's credit is 16 messages. Everything A sent that B has not yet confirmed counts against
				it, signals included: so far only <code>OpenChannel</code>, 1 of 16. Bytes are limited the
				same way.</li>
			</ul>`,
	},
	{
		id: 's1-send',
		stage: S2,
		title: 'Two sends, each gated by credit',
		body: `
			<ul>
				<li>The app calls <code>send(B, 0, 0, data)</code>. The runtime checks the credit and appends
				the message to this block's outbox (<code>OutboundMessages</code>).</li>
				<li>Each stream is a Merkle Mountain Range (MMR), an append-only Merkle structure. The runtime
				stores only its frontier, a few peak hashes, never the messages themselves.</li>
				<li>The new messages take the next positions, #1 and #2. During the block, the stored frontier
				still covers only #0.</li>
			</ul>`,
	},
	{
		id: 's1-bag',
		stage: S2,
		title: 'Block end: bag the data stream',
		body: `
			<ul>
				<li>At the end of the block, the runtime adds #1 and #2 to the frontier in memory: #1 merges
				with #0 into a peak, #2 starts a new one.</li>
				<li>Hashing the peaks together (bagging) gives the stream's root. It is never stored; it is
				always recomputed from the frontier.</li>
			</ul>`,
	},
	{
		id: 's1-fold',
		stage: S2,
		title: 'Fold all streams into one root',
		body: `
			<ul>
				<li>A's <code>StreamsRoot</code> is the root of a small Merkle trie over all its streams, keyed
				by stream id. Only the paths of changed streams are recomputed.</li>
				<li>The new root T<sub>A2</sub> is the single hash A publishes for block N. It goes into the block
				header, and during validation it is handed to JAM (host function 204).</li>
				<li>A block that changes no stream publishes no root.</li>
			</ul>`,
	},
	{
		id: 's1-outputs',
		stage: S2,
		title: 'What leaves the block',
		body: `
			<ul>
				<li>T<sub>A2</sub> is in A's block header, where other chains' collators can check against it.</li>
				<li>A's collator copies the block's messages, #1 and #2, into its archive. The archive is
				local disk, not chain state.</li>
				<li>At the start of block N+1, the runtime folds #1 and #2 into the stored frontier.</li>
			</ul>`,
	},
	// ── Block N settles on JAM ──
	{
		id: 's2-package',
		stage: S3,
		title: 'A work package for block N',
		body: `
			<ul>
				<li>A's collator wraps block N and its PoV into a work package for the Parachain Service.</li>
				<li>Guarantors on A's core pick it up and run Refine.</li>
			</ul>`,
	},
	{
		id: 's2-refine',
		stage: S3,
		title: 'Refine re-executes block N',
		body: `
			<ul>
				<li>Refine is the backing step: it runs A's validation code on the PoV, re-executing block N.</li>
				<li>The validation code reports its results through host functions. Function 204 declares
				T<sub>A2</sub>, the same root block N put into its header.</li>
				<li>Function 205 declares dependencies on other chains. Block N read nothing from other chains,
				so it is not called.</li>
			</ul>`,
	},
	{
		id: 's2-join',
		stage: S3,
		title: 'Guaranteed and available',
		body: `
			<ul>
				<li>JAM validators guarantee the result (the work report), and the package's data is made
				available.</li>
				<li>Only then does JAM pass the result to the Parachain Service's Accumulate.</li>
			</ul>`,
	},
	{
		id: 's2-accumulate',
		stage: S3,
		title: 'Accumulate checks, then enacts',
		body: `
			<ul>
				<li>Accumulate is the inclusion step, the counterpart of <code>enact_candidate</code>. It runs a
				fixed list of checks.</li>
				<li>Checks 1–4: block N must build on A's current head and use A's current code.</li>
				<li>Check 5 is the messaging check. Block N depends on no other chain, so it passes
				trivially; B's block M is checked here for real.</li>
			</ul>`,
	},
	{
		id: 's2-enact',
		stage: S3,
		title: "T<sub>A2</sub> lands in A's ring",
		body: `
			<ul>
				<li>Accumulate updates A's head and stores T<sub>A2</sub> in A's settlement ring. The head marker
				moves to the next free slot.</li>
				<li>The ring keeps A's last 64 roots. Any block of another chain may now depend on T<sub>A2</sub>,
				as long as it stays in the ring.</li>
			</ul>`,
	},
	// ── B fetches the messages ──
	{
		id: 's3-notice',
		stage: S4,
		title: "B's collator sees T<sub>A2</sub> in A's ring",
		body: `
			<ul>
				<li>B's collator watches A's ring and sees the new root T<sub>A2</sub>.</li>
				<li>B's runtime tells it which streams B reads, and from which position: A's data stream, from
				#0. B has not consumed anything yet, not even <code>OpenChannel</code>.</li>
				<li>B builds on T<sub>A2</sub> because it is already settled on JAM: B's block cannot fail because
				of A.</li>
			</ul>`,
	},
	{
		id: 's3-fetch',
		stage: S4,
		title: "B asks A's collator for the messages",
		body: `
			<ul>
				<li>B's collator asks A's collators for A's data stream from #0, proven against T<sub>A2</sub>
				(a <code>MessagesRequest</code>).</li>
				<li>A's collator answers from its archive: <code>OpenChannel</code>, m<sub>1</sub> and
				m<sub>2</sub>, plus the proofs that tie them to T<sub>A2</sub>.</li>
				<li>Messages are addressed by stream and position, not by block: B does not need to know which
				of A's blocks wrote them.</li>
			</ul>
			<p class="key"><strong>The key split.</strong> On-chain, the Parachain Service only
			stores 32-byte roots, one per block that sent messages. The messages and the proofs that tie them
			to a root travel collator to collator, off-chain. That keeps JAM's work small.</p>`,
	},
	{
		id: 's3-verify',
		stage: S4,
		title: 'B checks the response',
		body: `
			<ul>
				<li>B's collator hashes the messages and appends them to its frontier for A's stream, empty so
				far. Order and count need no separate check: anything else would give a different root.</li>
				<li>The proofs then lead from that stream root to A's <code>StreamsRoot</code>. B is caught
				up, so the trie proof alone is enough.</li>
				<li>The result equals T<sub>A2</sub>, which B read from JAM itself. The response is authentic.</li>
			</ul>`,
	},
	// ── B consumes them ──
	{
		id: 's4-inherent',
		stage: S5,
		title: "B's collator starts block M",
		body: `
			<ul>
				<li>B's collator starts block M and puts the verified messages into its messaging inherent, as
				A did with the register.</li>
				<li>The inherent carries only the messages, no root and no proofs. Binding them to T<sub>A2</sub>
				happens later, during validation.</li>
			</ul>`,
	},
	{
		id: 's4-consume',
		stage: S5,
		title: 'B consumes #0–#2',
		body: `
			<ul>
				<li>B's runtime hashes each message and appends it to its frontier for A's stream: 0 → 3
				messages. That is the runtime's only check.</li>
				<li><code>OpenChannel</code> is consumed like any message; m<sub>1</sub> and m<sub>2</sub> go
				to B's application.</li>
				<li>The block records what it consumed: A's data stream, positions 0 to 3. B sent nothing,
				so its root stays T<sub>B1</sub>.</li>
			</ul>`,
	},
	{
		id: 's5-package',
		stage: S5,
		title: 'Block M goes to JAM, with a lift',
		body: `
			<ul>
				<li>B's collator wraps block M into a work package, as A did.</li>
				<li>The PoV also carries a <em>lift</em>: a proof that what B consumed from A's stream is
				contained in a root of A that JAM knows. Here it is a single trie proof, about 300 bytes.</li>
			</ul>`,
	},
	{
		id: 's5-refine',
		stage: S5,
		title: 'Validation turns consumption into a dependency',
		body: `
			<ul>
				<li>After re-executing block M, B's validation code reads the consumption record and checks
				the lift: the 3 consumed messages lead to A's <code>StreamsRoot</code> T<sub>A2</sub>.</li>
				<li>It declares the dependency with host function 205: <code>[(A, T<sub>A2</sub>)]</code>.</li>
				<li>The Parachain Service only checks the form of that list. Proving the lift is the job of
				B's own validation code, like everything else in the block.</li>
			</ul>`,
	},
	// ── Block M settles ──
	{
		id: 's5-settle',
		stage: S6,
		title: "Check 5: is T<sub>A2</sub> in A's ring?",
		body: `
			<ul>
				<li>Accumulate looks up (A, T<sub>A2</sub>) in A's settlement ring. It is there, so block M is
				accepted and B's head moves to M.</li>
				<li>Had it been missing, B's block would be dropped without any log entry, together with all
				its upward messages.</li>
				<li>Only roots already in the ring count: B's block can never depend on a root of A that JAM
				has not settled yet.</li>
			</ul>`,
	},
	// ── Credit flows back ──
	{
		id: 'ov-republish',
		stage: S7,
		title: 'B confirms with a new register',
		body: `
			<ul>
				<li>When B has consumed enough (for example a quarter of the credit) or enough time has passed,
				it appends a new <code>Register</code> with <code>up_to 3</code>: everything before #3 is
				consumed.</li>
				<li>B's block commits a new root T<sub>B2</sub>; B's collator archives the register.</li>
				<li>T<sub>B2</sub> is stored in B's settlement ring.</li>
			</ul>`,
	},
	{
		id: 'ov-credit',
		stage: S7,
		title: 'Credit flows back to A',
		body: `
			<ul>
				<li>A's collator fetches the new register, checked against T<sub>B2</sub>.</li>
				<li>A's next block imports it. Messages before #3 are confirmed, so nothing is in flight any
				more: A has its full credit again.</li>
				<li>A may now delete #0–#2 from its archive: B confirmed them under a settled root, so this
				cannot be undone.</li>
			</ul>`,
	},
	{
		id: 'summary',
		stage: S7,
		title: 'The whole picture',
		body: `
			<ul>
				<li>A sent m<sub>1</sub> and m<sub>2</sub>, B consumed them, and B's register returned the
				credit.</li>
				<li>The register took the same path the other way: A fetched and checked it, consumed it
				through an inherent, and A's block passed the settlement check against T<sub>B1</sub>.</li>
				<li>JAM stored a few 32-byte roots and checked one dependency per block. All messages and
				proofs stayed with the two chains.</li>
			</ul>`,
	},
]
