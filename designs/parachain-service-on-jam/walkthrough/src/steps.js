// Narration for each step. `id` doubles as the timeline label in main.js.
// Refs: SM = speculative-messaging-design.md, PS = parachain-service-on-jam.md.
// The scene shows *what* changes; the panel explains *why*.

const stage = 'Stage 0 · Channel setup'
const stage1 = 'Stage 1 · A authors a block'
const stage2 = 'Stage 2 · Block N through JAM'
const stage3 = 'Stage 3 · B fetches the messages'
const stage4 = 'Stage 4 · B consumes them'
const stage5 = "Stage 5 · B's block settles"
const stage6 = 'Stage 6 · Credit flows back to A'

export const steps = [
	{
		id: 'goal',
		stage: 'Overview',
		title: 'Messages between two parachains',
		body: `
			<p><strong>Goal:</strong> parachain A sends messages to parachain B.</p>
			<ul>
				<li>Messages travel over a <strong>channel</strong>. Channels are unidirectional:
				A→B lets A write and B read. Replies would need a second channel B→A.</li>
				<li>The chains exchange the messages themselves off-chain. JAM's Parachain
				Service only settles 32-byte roots that commit to them.</li>
				<li>This walkthrough follows the <strong>inclusion tier</strong>: B consumes only
				what JAM has already settled for A.</li>
			</ul>`,
		ref: 'SM (speculative-messaging-design.md) · PS (parachain-service-on-jam.md)',
	},
	{
		id: 'intro',
		stage,
		title: 'Before any data flows, A and B need a channel',
		body: `
			<p>A wants to send messages to B. A channel is a pair of streams:
			<strong>data</strong>, written by A and read by B, and <strong>ack</strong>,
			written by B and read by A.</p>
			<p>Everything in this stage is parachain runtime and collator work. The
			Parachain Service on JAM only ever settles roots.</p>`,
		ref: 'SM §Channels and Flow Control',
	},
	{
		id: 'anatomy',
		stage,
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
	{
		id: 'open',
		stage,
		title: 'A opens the channel',
		body: `
			<ul>
				<li><code>OpenChannel</code> becomes leaf #0 of A's data stream. It is the only
				message A may send without credit, because B has not granted any yet.</li>
				<li>A's channel state (<code>OutChannels</code>) starts in phase
				<em>Opening</em>: no register from B yet.</li>
				<li>Nothing reaches B. How A's wish to open is communicated is outside the
				transport; B decides on its own whether to accept.</li>
			</ul>`,
		ref: 'SM :1748 (Opening)',
	},
	{
		id: 'commitA',
		stage,
		title: "A's new root settles on JAM",
		body: `
			<ul>
				<li>Appending a leaf changes the data stream's MMR root, which folds into A's
				commitment trie: the new <code>StreamsRoot</code> T<sub>A1</sub>.</li>
				<li>A's collator copies the block's sends into its node-local archive
				(via <code>outbound_messages()</code>): position #0, <code>OpenChannel</code>.</li>
				<li>In Refine, A's validation code declares the root via host fn 204.
				Accumulate enacts the block and pushes the root into A's settlement ring.</li>
				<li>Settlement is per root: the service never learns which stream changed,
				or that a channel exists at all.</li>
			</ul>`,
		ref: 'PS host fn 204 (:802), §8.1 Settlement Ring',
	},
	{
		id: 'accept',
		stage,
		title: 'Someone on B submits accept_open_channel',
		body: `
			<ul>
				<li>Accepting is a signed transaction on B, the analog of
				<code>hrmp_accept_open_channel</code>. It reaches B's runtime like any other
				extrinsic: B's collator includes it in B's next block.</li>
				<li>There is no push path and no <code>AcceptChannel</code> signal from A's side.</li>
				<li>B's policy decides the origin and any deposit.</li>
				<li>Order is free: B may accept before A opens, or A's open leaf may wait
				until B accepts.</li>
			</ul>`,
		ref: 'SM :1758',
	},
	{
		id: 'publishB',
		stage,
		title: 'B accepts and publishes its first Register',
		body: `
			<ul>
				<li>B records the channel in <code>InChannels</code> and starts reading A's
				data stream from #0.</li>
				<li>B's ack stream gets a <code>Register</code> as leaf #0. Its grant is A's
				credit: absolute limits on messages, bytes and message size beyond
				<code>up_to</code>.</li>
				<li>B enforces nothing. A gates its own sends on the grant, which bounds
				A's archive and surfaces backpressure to A's applications.</li>
			</ul>`,
		ref: 'SM :1741 (WindowGrant)',
	},
	{
		id: 'commitB',
		stage,
		title: "Publishing is a send, so B's root moves too",
		body: `
			<p>Same path as A's: new <code>StreamsRoot</code> T<sub>B1</sub>, host fn 204
			in Refine, enactment in Accumulate, push into B's settlement ring.</p>
			<p>B's collator archives the Register leaf, so it can serve it to A later.</p>`,
		ref: 'PS §5.1 step 6',
	},
	{
		id: 'notice',
		stage,
		title: "A's collator notices B's ring moved",
		body: `
			<ul>
				<li>Every JAM block, A's collator reads B's ring head
				(<code>messages_cursor</code>, tag 0x09). It advanced, and the new root
				T<sub>B1</sub> sits right behind it (<code>messages_queue</code>, tag 0x0b).</li>
				<li>A root change does not say which stream moved, so A asks for each stream
				it reads from B: here only the ack stream.</li>
			</ul>`,
		ref: 'PS storage tags (:523)',
	},
	{
		id: 'fetch',
		stage,
		title: 'Fetch the register under the enacted root',
		body: `
			<ul>
				<li>The request names a stream and a root:
				<code>EventRequest{stream: Ack{A,0,0}, at: None, under: T<sub>B1</sub>}</code>.</li>
				<li>The response is the leaf with an MMR inclusion proof and a tree proof.
				A's collator checks them against exactly T<sub>B1</sub>: trust is keyed by
				root, never by block.</li>
			</ul>
			<p class="key"><strong>The key split.</strong> On-chain, the Parachain Service only
			stores 32-byte roots, one per enacted block. The messages themselves and the
			proofs that tie them to a root travel collator to collator, off-chain. That is
			what keeps settlement cheap.</p>`,
		ref: 'SM :905 (EventRequest), :1952',
	},
	{
		id: 'import',
		stage,
		title: 'A imports the register; the channel is Open',
		body: `
			<ul>
				<li>A's collator puts the leaf and its proof into A's next block as the
				messaging inherent, the collator-made counterpart of B's accept tx. A's runtime
				verifies again and stores the register in <code>OutChannels</code>: the channel
				is Open, and A holds credit to send data.</li>
				<li>Reading B's ack stream is itself a consumption. A's validation will emit
				<code>requires (B, T<sub>B1</sub>)</code> via host fn 205, so A's block only
				settles while T<sub>B1</sub> is in B's ring.</li>
			</ul>`,
		ref: 'PS host fn 205 (:803)',
	},
	{
		id: 'summary',
		stage,
		title: 'What the Parachain Service saw',
		body: `
			<p>Two roots: T<sub>A1</sub> in A's ring and T<sub>B1</sub> in B's ring. Nothing else.</p>
			<ul>
				<li>Frontiers are eternal. Close and reopen touch only channel state,
				so there are no channel epochs.</li>
				<li>From the first register read onward, A depends on B's roots.</li>
			</ul>
			<p>Next: Stage 1, A authors a block with data.</p>`,
		ref: '',
	},

	// ── Stage 1 ──
	{
		id: 's1-intro',
		stage: stage1,
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
		stage: stage1,
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
		stage: stage1,
		title: 'Block end: bag the data stream',
		body: `
			<ul>
				<li>In memory, the runtime appends this block's leaves to the frontier: #1 merges
				with #0 into a peak, #2 starts a new one.</li>
				<li>Bagging the peaks gives the data stream's MMR root. No stream root is stored
				anywhere; it is always recomputed from the frontier.</li>
			</ul>`,
		ref: 'SM :640 (MmrFrontier), :694 (sender lifecycle)',
	},
	{
		id: 's1-fold',
		stage: stage1,
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
		stage: stage1,
		title: 'What leaves the block',
		body: `
			<ul>
				<li>T<sub>A2</sub> is deposited as A's header digest
				(<code>DigestItem::Consensus</code>, at most one per header).</li>
				<li>A's collator pulls the block's sends through the runtime API
				<code>outbound_messages()</code> and appends them to its archive at positions
				#1 and #2. Collators never read messaging storage directly.</li>
				<li>The archive is node-local disk, not chain state: the runtime keeps only the
				frontier. B's collators will fetch m<sub>1</sub> and m<sub>2</sub> from here, and A may
				prune them only once B's register confirms consumption.</li>
			</ul>`,
		ref: 'SM :728 (runtime API), :2039 (archive pruning), :2573',
	},
	{
		id: 's1-summary',
		stage: stage1,
		title: 'Block N is sealed; JAM knows nothing yet',
		body: `
			<ul>
				<li>Off-chain: m<sub>1</sub> and m<sub>2</sub> in A's archive, T<sub>A2</sub> in
				A's header.</li>
				<li>On-chain: A's ring still holds only T<sub>A1</sub>. T<sub>A2</sub> lands
				there once JAM enacts block N.</li>
				<li>At block N+1 init, the frontier absorbs #1 and #2 and
				<code>OutboundMessages</code> is cleared, in one step.</li>
			</ul>
			<p>Next: Stage 2, A's collator submits block N to JAM.</p>`,
		ref: '',
	},

	// ── Stage 2 ──
	{
		id: 's2-package',
		stage: stage2,
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
		stage: stage2,
		title: 'Refine re-executes block N',
		body: `
			<ul>
				<li>Refine takes the para id from the authorizer config, fetches the validation
				code by hash and runs <code>jam_validate_block</code> in a child PVM.</li>
				<li>The validation code reports through host calls. 200 and 201 are mandatory;
				204 declares T<sub>A2</sub>, the same root block N put in its header digest.</li>
				<li>205 is not called: block N consumed nothing, so it depends on no other chain.</li>
			</ul>`,
		ref: 'PS §4.1, §4.3 (host fns 200–205), §3.3 (work digest)',
	},
	{
		id: 's2-join',
		stage: stage2,
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
		stage: stage2,
		title: 'Accumulate checks, then enacts',
		body: `
			<ul>
				<li>Each report pays for itself: the gas gate skips any report whose own gas
				limit cannot cover it.</li>
				<li>Checks 1–4 make sure block N extends A's current head with A's current code.</li>
				<li>Check 5 is the messaging check. Block N requires nothing, so it passes
				trivially. A block that consumed messages is checked here against the
				senders' rings.</li>
			</ul>`,
		ref: 'PS §5.1 (per-work-package work)',
	},
	{
		id: 's2-enact',
		stage: stage2,
		title: "T<sub>A2</sub> lands in A's ring",
		body: `
			<ul>
				<li>Enactment writes block N's head data and pushes T<sub>A2</sub> at the ring's
				head. The head moves on to the next free slot.</li>
				<li>Accumulate also returns a Merkle root over the heads it changed. That root is
				JAM's commitment to the new head of A.</li>
			</ul>`,
		ref: 'PS §5.1 step 6, §5.5 (head commitment), §8.1 (pushing a root)',
	},
	{
		id: 's2-summary',
		stage: stage2,
		title: 'Block N is settled',
		body: `
			<ul>
				<li>A's ring now holds T<sub>A1</sub> and T<sub>A2</sub>. Any block of B that
				consumes m<sub>1</sub> and m<sub>2</sub> can name T<sub>A2</sub> and is sure to
				pass check 5, as long as T<sub>A2</sub> stays in the 64-entry window.</li>
				<li>That is the inclusion tier: B depends only on roots JAM has already
				settled.</li>
			</ul>
			<p>Next: Stage 3, B's collator fetches m<sub>1</sub> and m<sub>2</sub>.</p>`,
		ref: '',
	},

	// ── Stage 3 ──
	{
		id: 's3-notice',
		stage: stage3,
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
		stage: stage3,
		title: 'Fetch by position, trust by root',
		body: `
			<ul>
				<li><code>MessagesRequest{stream: Channel{B,0,0}, start: 0, under: T<sub>A2</sub>,
				max_bytes}</code> goes to A's collators.</li>
				<li>A's collator answers from its archive: payloads #0–#2 (OpenCh, m<sub>1</sub>,
				m<sub>2</sub>), an extension proof and a tree proof that tie them to T<sub>A2</sub>.</li>
				<li>Addressing is by stream and position, never by block: B never has to look
				for which of A's blocks wrote to its stream.</li>
			</ul>`,
		ref: 'SM :820 (fetch protocol)',
	},
	{
		id: 's3-verify',
		stage: stage3,
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

	// ── Stage 4 ──
	{
		id: 's4-inherent',
		stage: stage4,
		title: "B's collator starts block M",
		body: `
			<ul>
				<li>The verified payloads go into block M's messaging inherent, the same path
				A used for the register in stage 0.</li>
				<li>The inherent carries payloads only, never a StreamsRoot. A root chosen by
				the block author would prove nothing to the runtime.</li>
			</ul>`,
		ref: 'SM :800 (inherent), :936',
	},
	{
		id: 's4-consume',
		stage: stage4,
		title: 'B consumes #0–#2',
		body: `
			<ul>
				<li>B's runtime hashes each payload into its leaf and appends it to
				<code>InboundFrontier</code> for A's data stream: leaf count 0 → 3. That
				recomputation is the runtime's only check.</li>
				<li><code>OpenChannel</code> is consumed in order like any message; m<sub>1</sub>
				and m<sub>2</sub> are handed to B's application.</li>
				<li>The block writes a consumption record: for A's data stream, where consumption
				started and where it ended.</li>
			</ul>`,
		ref: 'SM :676 (InboundFrontier), :1244 (consumption record)',
	},
	{
		id: 's4-summary',
		stage: stage4,
		title: 'Block M consumed, but names no root',
		body: `
			<ul>
				<li>Block M records what it consumed, not which root it trusted. It never sees
				T<sub>A2</sub>.</li>
				<li>Block M sent nothing, so B's StreamsRoot is still T<sub>B1</sub> and block M
				publishes no root.</li>
			</ul>
			<p>Next: binding block M to T<sub>A2</sub> is the validation wrapper's job.</p>`,
		ref: '',
	},

	// ── Stage 5 ──
	{
		id: 's5-package',
		stage: stage5,
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
		stage: stage5,
		title: 'The wrapper turns consumption into a requirement',
		body: `
			<ul>
				<li>After executing block M, the validate_block wrapper reads the consumption
				record and stitches the intervals of all blocks in the candidate. One block,
				one interval: the endpoint is frontier(3).</li>
				<li>The lift carries the endpoint to a committed root: extension (empty) to the
				stream root, tree proof to A's StreamsRoot T<sub>A2</sub>.</li>
				<li>Host fn 205 declares <code>[(A, T<sub>A2</sub>)]</code>. The service's Refine
				only checks the shape (at most 32 sources, no duplicates, not itself); proving
				the lift is the parachain's own code.</li>
			</ul>`,
		ref: 'SM :1330 (build_requires); PS host fn 205 (:803)',
	},
	{
		id: 's5-settle',
		stage: stage5,
		title: 'Check 5: is T<sub>A2</sub> in A\'s ring?',
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
	{
		id: 's5-summary',
		stage: stage5,
		title: 'm<sub>1</sub> and m<sub>2</sub> are delivered',
		body: `
			<ul>
				<li>B's block M is enacted, and it is enacted only because the root it depends
				on is settled.</li>
				<li>The service compared two 32-byte hashes. Every payload and proof stayed with
				the two chains.</li>
			</ul>
			<p>Next: A still counts the three messages as in flight. Credit has to flow back.</p>`,
		ref: '',
	},

	// ── Stage 6 ──
	{
		id: 's6-publish',
		stage: stage6,
		title: 'B republishes its register',
		body: `
			<ul>
				<li>B publishes a new <code>Register</code> once consumption has advanced far
				enough (e.g. a quarter of the window) or an age threshold passes.</li>
				<li>Leaf #1 on B's ack stream: <code>up_to 3</code>, same grant. Only the latest
				leaf matters; it supersedes #0.</li>
				<li>Publishing is a send, so B's StreamsRoot becomes T<sub>B2</sub>, and B's
				collator archives the leaf.</li>
			</ul>`,
		ref: 'SM :1942 (publishing), :1885 (Register)',
	},
	{
		id: 's6-settle',
		stage: stage6,
		title: 'T<sub>B2</sub> settles in B\'s ring',
		body: `
			<p>Same pipeline as stage 2, for B's block M+1: work package, Refine with host
			fn 204, Accumulate pushes T<sub>B2</sub> into B's ring.</p>`,
		ref: 'PS §5.1 step 6',
	},
	{
		id: 's6-read',
		stage: stage6,
		title: "A's collator reads the new register",
		body: `
			<ul>
				<li>B's ring moved, so A's collator asks again:
				<code>EventRequest{Ack{A,0,0}, at: None, under: T<sub>B2</sub>}</code>.</li>
				<li><code>under</code> fixes the head: an old leaf cannot be served as the head
				under T<sub>B2</sub>. The response verifies against T<sub>B2</sub>.</li>
			</ul>`,
		ref: 'SM :1952 (reading, sender side)',
	},
	{
		id: 's6-import',
		stage: stage6,
		title: 'Credit is back',
		body: `
			<ul>
				<li>A's next block imports the register. In flight counts positions ≥
				<code>up_to</code>, and <code>up_to</code> is now 3: 0 of 16 messages in flight.</li>
				<li>That block's init also absorbed m<sub>1</sub> and m<sub>2</sub> into the stored
				frontier, as stage 1 said it would.</li>
				<li>The read creates <code>requires (B, T<sub>B2</sub>)</code>: A's block settles
				only while T<sub>B2</sub> is in B's ring.</li>
			</ul>`,
		ref: 'SM :1937 (window accounting)',
	},
	{
		id: 's6-prune',
		stage: stage6,
		title: 'A may prune its archive',
		body: `
			<ul>
				<li>A may drop payloads below the watermark once the register asserting it is
				irreversible at the tier in use.</li>
				<li>Read under a settled root, it is irreversible by definition. #0–#2 can go;
				the stored frontier still lets A extend the stream.</li>
			</ul>`,
		ref: 'SM :2039 (archive pruning)',
	},
	{
		id: 's6-summary',
		stage: stage6,
		title: 'The loop is closed',
		body: `
			<ul>
				<li>A sent m<sub>1</sub> and m<sub>2</sub>; B consumed them; B's register gave the
				credit back; A pruned what it no longer needs.</li>
				<li>On JAM: two roots in each ring, and two membership checks. Everything else
				was runtime and collator work.</li>
				<li>Each direction depended only on roots already settled: the inclusion tier.</li>
			</ul>`,
		ref: '',
	},
]
