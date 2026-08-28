# Long-range attacks — exposure analysis and mitigations

Research date: 2026-08-28, against the `30.2` branch (Qtum v30.2 /
Bitcoin Core 30.2 layer). Live-chain figures taken from mainnet at
height **2,796,761**.

This document answers three questions: what a long-range attack is in a
UTXO proof-of-stake chain, how exposed Runebase actually is once the
Qtum-inherited defences are accounted for, and what to do about it.

**Verdict: better protected than most PoS chains against *online* nodes,
because of an inherited hard max-reorg rule that is easy to overlook.
Materially exposed for *bootstrapping* and *long-offline* nodes, because
the hardened checkpoints are 1.5 years stale.** The highest-value fix is
free: refresh the checkpoints every release. The remaining exposure is
weak subjectivity, which no pure-PoS protocol removes without a finality
gadget or an external anchor.

## 1. The attack

In proof-of-work, rewriting history costs hashes: real time, real
electricity, redone from the fork point. In proof-of-stake a block is
valid if a UTXO's kernel hash beats a target
(`CheckStakeKernelHash`, `src/pos.cpp:64`), so a party holding — or
acquiring — private keys that controlled coins at some past height H can
*simulate* an entirely alternative history from H forward, offline, at
CPU speed, and present it as a competing chain.

Three properties make it work:

**Costless simulation.** Building 1.4M alternative blocks is a
laptop-hour, not a year of electricity. The only real-time constraint is
the timestamp ceiling, and Runebase's is tight — `FutureDrift`
(`src/validation.cpp:170`) allows `nTime + 15` seconds only. That stops
an attacker extending into the *future*; it does nothing about rewriting
the *past*, where every timestamp they need is already historical.

**Posterior corruption.** The keys required are keys to coins that
existed at H — not coins the attacker owns today. Those coins may have
been spent, sold, or held by an exchange that shut down years ago. To
their former owners the keys are worthless, which makes them cheap to
buy and easy to leak. This is the crux of the attack class: it is
carried out with stake somebody *used to* own.

**Stake grinding.** The stake modifier is
`hash(kernel ‖ prevModifier)` (`ComputeStakeModifier`, `src/pos.cpp:35`),
so each block's modifier depends on the block just chosen. A simulator
therefore explores a *tree*: pick a different winning UTXO or a
different 16-second timestamp slot at height h, get a different modifier
at h+1, retry. An honest staker gets one attempt per slot; a simulator
gets as many as it cares to compute. Effective stake is consequently
higher than nominal stake, by a factor that grows with the compute
budget.

Nothing in PoSv3 penalises this. There is no slashing — signing two
conflicting histories carries no cost — and no finality gadget. The
protocol makes long-range attacks *inconvenient*, never *expensive*.

## 2. What already bounds it (verified in source)

Runebase inherits three defences from Qtum that Bitcoin Core does not
have. They are real and they change the answer substantially.

### 2.1 The hard max-reorg rule — the load-bearing defence

`BlockManager::CheckSync` (`src/node/blockstorage.cpp:1067`) walks back
`CheckpointSpan` blocks from the node's **own current tip**
(`AutoSelectSyncCheckpoint`, `:1055`) and rejects any incoming block or
header at or below that height. It is enforced twice:

- `ContextualCheckBlockHeader`, `src/validation.cpp:5946` →
  `bad-fork-prior-to-synch-checkpoint`
- `AcceptBlock`, `src/validation.cpp:6333` → `checkpoint-conflict`

`nRBTCheckpointSpan` is 2000 blocks (`src/kernel/chainparams.cpp:237`,
selected by `Consensus::Params::CheckpointSpan`,
`src/consensus/params.h:255`) = **17.8 hours** at 32 s/block. Past that
depth a competing fork is not out-worked, it is not even parsed — the
headers are rejected before fork choice runs.

A background thread reinforces this by *deleting* side-branch block
indexes older than the span (`NeedToEraseBlockIndex`,
`src/net_processing.cpp:6468`, driven from `CleanBlockIndex`, `:6507`),
so a node cannot be walked back into a stale branch later.

This is a deliberate safety-over-liveness trade and it cuts both ways —
see §5.

### 2.2 Hardened checkpoints, re-checked during block connection

Unlike Bitcoin's advisory checkpoints, `BlockManager::CheckHardened`
(`src/node/blockstorage.cpp:1046`) is called from **`ConnectBlock`**
(`src/validation.cpp:3470`) as well as from `ContextualCheckBlockHeader`
(`:5941`). History through the last checkpointed height is therefore
immutable regardless of accumulated work. Enabled by default;
`-checkpoints=0` is `DEBUG_ONLY` (`src/init.cpp:666`).

### 2.3 Minimum chain work and assumevalid

`consensus.nMinimumChainWork` and `consensus.defaultAssumeValid`
(`src/kernel/chainparams.cpp:150-151`) stop a fresh node being led down
a low-work header chain, and the header spam filter
(`src/net_processing.cpp:1706`, `-headerspamfilter*`) limits the cost of
being fed junk headers.

## 3. Exposure, honestly

**A node that stays online: effectively not vulnerable.** The 2000-block
rule makes deep reorgs structurally impossible rather than merely
expensive. This is a stronger position than most PoS chains occupy.

**A fresh node, or one offline more than ~18 hours: vulnerable.**
`CheckSync` anchors to the node's *own* tip, so a node returning after a
week of downtime can be reorged from wherever it left off, and a node
syncing from scratch is protected only by chain work. During IBD the PoS
kernel is not even checked on headers — `CheckBlockHeader` skips
`CheckHeaderPoS` while `IsInitialBlockDownload()`
(`src/validation.cpp:5625`), necessarily, since kernel validation needs
a UTXO set the node does not yet have.

This is textbook **weak subjectivity**: a new node's correctness depends
on obtaining a recent trusted reference point, which the protocol alone
cannot supply.

**And Runebase's reference point is badly stale.**

| | value |
|---|---|
| Current mainnet height | 2,796,761 |
| Last hardened checkpoint | **1,347,735** (`src/kernel/chainparams.cpp:205`) |
| Gap | 1,449,026 blocks = **536 days ≈ 1.5 years** |
| Chain work after the last checkpoint | **52.6%** of all chain work ever produced |
| `nMinimumChainWork` / `defaultAssumeValid` | also pinned at 1,347,735 |
| Money supply | 208,168,850 RUNES |
| `netstakeweight` | 32.44M RUNES = **15.58% of supply** |

The last row is the real security budget. Difficulty tracks *actively
staking* weight, not total supply (`GetPoSKernelPS`,
`src/rpc/blockchain.cpp:151`), so the bar for out-working the honest
chain over a given span is roughly 15.6% of coins — **not 51%** — before
any grinding advantage is counted. Treat the figure as an estimate: it
is derived from difficulty over a 72-block window, not measured
directly.

An attacker's private fork reaches its own sustainable difficulty almost
immediately. The retarget EMA interval is `nRBTPowTargetTimespan /
nRBTPowTargetSpacing` = 1000/32 = 31 blocks, and
`CalculateNextWorkRequired` (`src/pow.cpp`) clamps `nActualSpacing` at
20× target, permitting up to a **3.28× target increase per block** — so
difficulty collapses to the attacker's level within about 16 minutes of
simulated time. That does not give them free work (total work still
scales with stake weight), but it does mean forking from an arbitrary
old height costs them almost nothing in ramp-up.

**Delegation is an amplifier.** Under offline staking, a super-staker's
key signs blocks for all of its delegated weight
(`CheckRecoveredPubKeyFromBlockSignature`, `src/pos.cpp:344`;
`CheckBlockInputPubKeyMatchesOutputPubKey`, `src/validation.cpp:3489`).
Compromising a small number of *historical* super-staker keys therefore
yields far more attack weight than those keys' owners personally held.

**Not a concern:** the height-1 premine (40M RUNES) and the whole PoW
era sit far below the last checkpoint, so `CheckHardened` protects them
absolutely even if those keys leak. Only coins that existed at or after
height 1,347,735 are usable for this attack.

## 4. Mitigations, in priority order

### 4.1 Refresh the checkpoints every release — do this next release

Free, uses machinery already in the tree, and collapses a 1.5-year
window to weeks. Update in `src/kernel/chainparams.cpp`:

- `checkpointData` (`:194`) — add a recent, deeply-buried height
- `consensus.nMinimumChainWork` (`:150`)
- `consensus.defaultAssumeValid` (`:151`) — also speeds up IBD

Do the same for testnet3, whose `nMinimumChainWork` and
`defaultAssumeValid` are still pinned at height 5000 (`:306-307`).

Add it to the standing release checklist, alongside the delegation
bytecode and the RIP-1 gate. Note this is a trust assumption — users
trust the release binary — but it is the assumption they already make by
running it, and it is how every production PoS chain handles weak
subjectivity.

**Caveat when adding entries:** every network's `checkpointData` must
keep a real `{0, <its genesis hash>}` entry, because `CheckHardened`
runs inside `ConnectBlock`. See the `{ { {}, } }` trap documented in
`CLAUDE.md`.

### 4.2 Publish weak-subjectivity checkpoints out-of-band

A signed feed of recent block hashes, plus documented `-assumevalid=<hash>`
usage (`src/init.cpp:505`) for operators bootstrapping between releases.
This covers the window that 4.1 leaves open for anyone syncing an older
binary. `-minimumchainwork` (`:532`) is available for the same purpose
but is `DEBUG_ONLY`.

### 4.3 Document and monitor the 2000-block rule

It is the load-bearing defence and it is currently undocumented. Two
operational consequences that people must learn *before* they hit them:

- Exchanges, bridges and payment processors have a hard bound: 2000
  confirmations (17.8 h) is absolute finality against an online node.
  Fewer confirmations is a policy choice about the ordinary 51%-style
  risk, not about long-range attacks.
- A genuine network partition lasting more than 17.8 hours **cannot heal
  automatically**. The minority side's nodes will reject the majority
  chain with `bad-fork-prior-to-synch-checkpoint` and need manual
  intervention. Watch for that string in logs; it is also the signature
  of an attempted deep reorg.

### 4.4 Anchor Runebase block hashes into Bitcoin

Periodically commit the tip hash into a Bitcoin transaction. This is the
only option that yields *objective* protection — a simulated history
cannot manufacture an earlier Bitcoin anchor — without introducing a
trusted committee, which the project's trust constraint rules out (see
`doc/runebase/bridges/README.md`, "Rejected up front").

Sequence it: start as a monitoring aid, where anyone can detect a chain
that contradicts the published anchors; only later consider making
anchor-consultation a consensus rule, which is a fork and a new external
dependency.

### 4.5 For outbound bridges specifically

This is exactly the outbound problem identified in
`doc/runebase/bridges/README.md`, and the figures above sharpen it. A
remote light client has neither a "chain I saw first" nor `CheckSync`,
so it must implement weak subjectivity explicitly:

- a checkpoint hardcoded at deployment,
- a max-reorg rule mirroring the node's 2000 blocks,
- a permissionless-with-challenge-window mechanism for advancing the
  checkpoint,
- confirmation-depth thresholds sized against §3's 15.6% figure, not
  against total supply.

4.4 would strengthen this considerably: a Bitcoin-anchored checkpoint is
verifiable by a contract on any chain that can already verify Bitcoin
headers.

### 4.6 Out of scope for now: a finality gadget

A BFT overlay with slashing is the textbook fix and the only one that
removes weak subjectivity outright. It is also a large consensus project
requiring a bonding mechanism that a UTXO chain does not naturally have.
4.1–4.4 buy most of the protection for a small fraction of the effort;
revisit this only if the chain's economic weight makes it worth the
engineering.

## 5. What this means for a secure bridge

The outbound bridge problem (`doc/runebase/bridges/README.md`) is the
place this analysis actually bites. Three concrete consequences.

**The 2000-block window is a protocol fact, not a heuristic.**
`02-ibc.md` proposes a level-1 client that "refuses reorgs deeper than a
bounded window W (e.g. 2000 blocks ~= 18h, matching coinbase maturity)".
That guess is now confirmed from source and is stronger than stated:
`nRBTCheckpointSpan` is *defined as* `nRBTCoinbaseMaturity`
(`src/kernel/chainparams.cpp:237`) and is enforced by `CheckSync` on
every Runebase node. A remote client that mirrors the rule is not
approximating full-node security — it is enforcing exactly what a full
node enforces. That is a defensible statement to put in front of an
auditor, and it means **level 1 is a legitimate design point, not a
compromise**.

**Relayer liveness becomes a security property.** A full node holds its
position by staying online. A bridge contract advances only when someone
submits headers. If the contract's checkpoint goes stale — no relayer
for longer than W — it drops straight back into the fresh-node weak
subjectivity hole of section 3, and its 2000-block rule now protects a
point 2000 blocks behind a *stale* tip, which is no protection at all.
So an outbound client must:

- track the newest header it has accepted, not just a checkpoint height;
- **halt** rather than accept a jump when its view is older than W,
  requiring a governance re-pin (the same recovery Tendermint clients
  use when the unbonding period expires);
- treat relaying as funded infrastructure, not best-effort.

This is the single largest delta between "a bridge as safe as a full
node" and "a bridge that is safe on paper".

**Size the bridge against staking weight, not supply.** Section 3 puts
the actively staking set at ~32.4M RUNES (15.6% of supply). Value locked
in an outbound bridge should be bounded well below the cost of acquiring
staking weight exceeding that figure, because an attacker who can
out-stake the network for a few hours can rewrite inside the window that
even a correctly-implemented level-1 client accepts. Confirmation-depth
thresholds and per-epoch transfer caps should both be derived from that
number and revisited as it moves; a bridge whose TVL exceeds the cost of
attacking the chain is a bridge that pays for its own exploit.

**Consequences for the other options:**

- **Inbound is unaffected.** Verifying a counterparty's consensus inside
  the Runebase EVM has nothing to do with Runebase's own finality. The
  sequencing in `bridges/README.md` stands unchanged.
- **HTLC atomic swaps (option 1) need a timelock floor.** A bounded
  reorg can still flip a claim into a refund if the timeout sits inside
  the reorg window. Set the Runebase-side CLTV timeout comfortably above
  2000 blocks — a claim deadline at >= 2000 blocks and a refund path
  opening at roughly double that — so no reachable reorg can invert the
  outcome. This constraint comes straight from `CheckSync` and should be
  a hard parameter, not a recommendation.
- **The zk-full-validation client (level 3) buys less than it appears
  to.** It does not raise the ceiling above full-node security; what it
  removes is the dependency on a live relayer and an initial trusted
  checkpoint. Valuable, but it is the *liveness* and *bootstrap*
  problem it solves, not the finality problem. Price the research
  accordingly.

**Prerequisite unchanged:** every outbound design still needs the
`getstateproof`-style RPC. The state trie has no Merkle-branch
extraction today (`GenericTrieDB`, `src/eth_client/libdevcore/TrieDB.h`)
and section 4.1's checkpoint refresh does nothing about it.

## 6. Design tension worth recording

The 2000-block rule trades liveness for safety, and it was inherited,
not chosen. If a future upgrade touches `nCheckpointSpan` /
`nRBTCheckpointSpan`, understand both directions:

- **Shorter span** → deep reorgs bounded more tightly, but a shorter
  partition becomes unhealable and honest nodes on slow links are more
  likely to reject valid chains.
- **Longer span** → more tolerance for partitions and offline nodes, but
  a wider window for an attacker who has out-staked the network.

Any change is consensus-visible and must be height-gated like every
other Runebase fork.

## 7. Reproducing the figures

```
runebase-cli getblockchaininfo    # blocks, chainwork, moneysupply
runebase-cli getstakinginfo       # netstakeweight, delegateweight

grep -n "nMinimumChainWork\|defaultAssumeValid" src/kernel/chainparams.cpp
sed -n '194,206p' src/kernel/chainparams.cpp          # mainnet checkpoints
grep -n "nCheckpointSpan\|nRBTCheckpointSpan" src/kernel/chainparams.cpp
```

Work after the last checkpoint, as a share of total:

```python
tot = int(<chainwork from getblockchaininfo>, 16)
cp  = int(<consensus.nMinimumChainWork>, 16)
print(100 * (tot - cp) / tot)
```
