# Option 3 — zk light-client bridge to Ethereum

Direct Runebase <-> Ethereum bridging without IBC's transport layer: run a
light client of each chain inside the other, verified either natively (via
precompiles) or as a zk proof. Same trust model as IBC — light clients plus
permissionless provers/relayers who can only delay, never forge — with less
protocol machinery and no Cosmos dependency.

## Direction 1: Ethereum -> Runebase (inbound)

Ethereum's consensus exposes a purpose-built hook for exactly this: the
**sync committee** (Altair) — 512 validators who BLS-sign every beacon
block header, rotating every ~27 hours, with each period's committee
committed in advance. Verifying Ethereum on another chain reduces to
verifying one aggregate BLS12-381 signature per update plus a Merkle branch
for committee rotation.

Two implementation routes, both viable on v29.1.0:

### Route A — native verification (post-Pectra, no prover at all)

Ethereum itself couldn't host this before its own Pectra added EIP-2537;
Runebase's Pectra fork ships the same suite (0x0b-0x11, live-verified on
regtest during the v29.1 work). Estimated gas per sync-committee update at
EIP-2537 prices:

| step | cost |
|---|---|
| aggregate <=512 participant pubkeys (G1 adds, 500 gas each) | <= ~256k |
| hash-to-curve of signing root (2x map_fp2_to_G2 + G2 ops) | ~50k |
| pairing check (2 pairings) | ~151k |
| SSZ/Merkle branches (sha256 precompile) | ~20k |
| **total** | **< ~500k gas** (~2 RUNES at the RIP-1 minimum) |

One update per ~27h period suffices for a slow bridge; per-block updates
for a fast one are still cheap. This route has **no prover
infrastructure** — a relayer posts publicly-available beacon data, and the
contract does all verification itself. Fewest moving parts, easiest to
audit, and unique among our options in requiring *zero* off-chain compute.

### Route B — zk-wrapped (works pre-Pectra, smaller proofs)

Run [Helios](https://github.com/a16z/helios)-class light-client logic in a
zkVM (SP1) and verify a Groth16 proof on Runebase via alt_bn128
(~230-300k gas, same verifier class as
[IBC Eureka](https://blog.succinct.xyz/ibc/) and
[zkBridge](https://arxiv.org/pdf/2210.00264)). Adds a permissionless prover
role; useful if we want one proof to compress many updates, or to follow
chains without a BLS-friendly hook.

Once headers are trusted, Ethereum state reaches Runebase contracts through
ordinary MPT storage proofs (keccak + RLP walking in Solidity — standard,
audited libraries exist). A lock-mint token bridge then follows: lock on
Ethereum, prove the lock's storage slot, mint wrapped asset on Runebase.

**Codebase requirements: none.** Contracts only.

## Direction 2: Runebase -> Ethereum (outbound)

Identical problem to IBC's outbound direction
(see [02-ibc.md](02-ibc.md#direction-2-runebase---cosmos-outbound--the-hard-problem)),
with Solidity instead of Wasm as the client host — the analysis transfers
one-to-one:

- headers are cheap to follow (181 bytes, sha256d, PoSv3 retarget math is
  simple integer arithmetic in Solidity),
- `hashStateRoot` in every header means accepted headers unlock standard
  MPT proofs of Runebase contract storage,
- but the stake kernel is unverifiable from headers alone, so security is
  weak-subjectivity + confirmation depth (level 1), extended prevout
  proofs (level 2), or zk full validation (level 3).

One Ethereum-specific extra: gas on Ethereum L1 is expensive, so the
header-following client is better hosted on an L2 (or updated via a
zk-compressed batch proof — prove "N headers extend checkpoint C" in SP1,
verify one Groth16 on L1). The level-3 zk client, if ever built, would be
shared verbatim between this option and IBC — build once, use twice.

Node-side additions: the same `getstateproof` / header-batch RPCs listed in
the IBC document. Build them once; every outbound design consumes them.

## Comparison against IBC

| | zk light-client (this) | IBC |
|---|---|---|
| counterparty reach | Ethereum + L2s (each added manually) | entire IBC network via one connection |
| protocol surface to audit | small (two clients + token app) | larger (ICS02/26/20 + apps) |
| inbound cost | ~0.5M gas native / ~250k zk | ~230k gas zk |
| off-chain infra | none (route A) or provers | provers + relayers |
| outbound problem | identical | identical |
| ecosystem momentum | per-project | an established standard |

**Recommended role:** the Ethereum native-verification inbound leg (route
A) is the single highest-value/lowest-complexity trustless component
available to us post-Pectra — worth building even if IBC is the long-term
strategy, since the token-bridge contracts and the outbound R&D are shared.
