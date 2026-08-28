# Option 2 — IBC (Inter-Blockchain Communication Protocol)

**Verdict up front:** IBC on Runebase is *feasible*, but the two directions
are wildly asymmetric. The inbound half (Cosmos-side chains -> Runebase) is
an engineering project on top of production open-source code, needs **no
consensus changes**, and every cryptographic requirement is already live in
the v29.1.0 EVM. The outbound half (Runebase -> Cosmos) requires writing a
Runebase light client for the counterparty, and Runebase's UTXO
proof-of-stake makes that the genuinely hard part — solvable, but with an
explicit, documented finality assumption rather than for free.

## What IBC actually requires

IBC is not a bridge product; it is a transport standard
([ICS-002](https://github.com/cosmos/ibc/blob/main/spec/core/ics-002-client-semantics/README.md))
with three roles:

1. **A light client of chain B running on chain A**, and vice versa. Each
   client verifies the counterparty's consensus and stores commitment
   roots.
2. **Provable state**: each chain must be able to prove packets
   (send/receive/ack commitments) against a root the counterparty's client
   trusts.
3. **Relayers** — in IBC these are **permissionless and untrusted by
   design**: they carry packets + proofs, and can censor/delay at worst,
   never forge. This satisfies the project's trust constraint by
   construction; it is the committee-style bridges that fail it, not IBC.

Since IBC v2 ("Eureka", live on Ethereum mainnet in 2025 via
[cosmos/solidity-ibc-eureka](https://github.com/cosmos/solidity-ibc-eureka)),
the protocol also has an official **Solidity implementation**, which is the
piece that makes an EVM-on-UTXO chain like Runebase a realistic target at
all: we deploy IBC as contracts, not as a Cosmos-SDK module.

## Direction 1: Cosmos -> Runebase (inbound) — engineering-grade

Architecture, mapped directly from Eureka's Ethereum deployment:

```
Cosmos chain ──(CometBFT header)──> SP1 prover (permissionless, anyone can run)
                                        │  Groth16 proof of Tendermint verification
                                        ▼
Runebase EVM:  ICS26 router ── ICS07 verifier contract ── ICS20 transfer app
                     ▲  alt_bn128 pairing precompiles (0x06-0x08, active since genesis)
relayer (permissionless) submits {packet, proof}
```

- The on-chain cost of verifying a whole Tendermint light-client update as
  a Groth16 proof is **~230k gas** in Eureka's production deployment
  ([Cosmos technical walkthrough](https://blog.cosmos.network/ibc-eureka-technical-walkthrough-0ba77c715baa)).
  Runebase's block gas limit is 40M; at the post-RIP-1 minimum of
  4000 sat/gas, one verification costs ~9.2 RUNES of gas — economically
  fine for transfer batching.
- The verifier needs only `alt_bn128` pairing — **live on Runebase since
  genesis** (Byzantium set). Nothing waits for Pectra here.
- Alternative stacks with the same shape: Datachain's
  [tendermint-zk-ibc](https://github.com/datachainlab/tendermint-zk-ibc) /
  [YUI ibc-solidity](https://github.com/hyperledger-labs/yui-ibc-solidity),
  and [Union](https://docs.union.build/architecture/cometbls/)'s
  CometBLS+Galois pipeline, whose relayer ("Voyager") and prover networks
  are explicitly permissionless. Union's BLS-heavy path benefits from our
  Pectra BLS12-381 precompiles (0x0b-0x11, verified live on regtest during
  the v29.1 work).
- **Non-zk fallback:** a plain Solidity Tendermint verifier (ed25519 over
  ~100+ validators) is what made pre-zk IBC-on-EVM expensive; Runebase has
  no ed25519 precompile, so the zk route is not just cheaper but the only
  practical one. This is fine — the zk route is the production-proven one.

**Verified against this codebase (regtest, 2026-08-25):**

- The Eureka contracts are built with solc 0.8.25+ targeting the `cancun`
  EVM. All the opcodes that target emits beyond older EVMs — PUSH0,
  TSTORE/TLOAD (transient storage), MCOPY — were exercised in deployed
  bytecode on a live node of this tree and behave correctly. Mainnet is
  past both gating forks (Shanghai 1340000, Cancun 1363636).
- The Groth16 substrate was proven by computation, not presence: a full
  bilinearity check `e(P,Q)·e(-P,Q) = 1` through the `alt_bn128` pairing
  precompile returned 1 on-chain. This is the same precompile family
  Eureka's `sp1-ics07` verifier calls on Ethereum.
- **Mandatory port-audit item:** Runebase consensus **bans `CREATE`/
  `CREATE2` with a value endowment** inside the EVM
  (`EVMC_CREATE_WITH_VALUE`, `src/evmone/lib/evmone/instructions_calls.cpp:345`
  — a deliberate Runebase patch). The Eureka stack's proxy/factory
  deployments are zero-value and unaffected, but every contract in the
  suite (and any escrow pattern layered on top) must be checked for
  value-bearing `new C{value: v}()` before deployment — on Runebase it
  reverts.
- Economics under RIP-1: a ~400-550k-gas `recvPacket` costs ~16-22 RUNES
  at the 4000 sat/gas minimum. Fine for transfers; worth batching for
  high-frequency flows.

Codebase requirements for this direction: **none consensus, none node.**
Contracts + an SP1 proving pipeline + any party running a relayer.

## Direction 2: Runebase -> Cosmos (outbound) — the hard problem

The counterparty needs a light client of Runebase. ibc-go's
[08-wasm](https://ibc.cosmos.network/main/ibc/light-clients/wasm/integration/)
module exists precisely for this: a custom client, written in Rust,
compiled to Wasm, uploaded by governance on the counterparty — no changes
to the counterparty chain's code. So the *mechanism* exists; the question
is what the client can actually verify.

### What a Runebase header gives a remote verifier

The 181-byte header contains: version, prev-hash, tx-merkle-root, time,
nBits, nonce, **hashStateRoot (EVM state)**, hashUTXORoot,
prevoutStake, and the staker's signature. A Wasm client can check, from
headers alone:

- chain linkage and the PoSv3 difficulty retarget arithmetic (nBits),
- timestamp rules (mask-16 slots, future drift),
- the staker's signature over the block,
- and once a header is accepted: **any EVM storage slot via a standard
  Merkle-Patricia proof against hashStateRoot** — the same proof format
  Ethereum clients verify, so existing MPT verifier code applies. Packet
  commitments written by an ICS26 contract on Runebase become provable.

### What it cannot check, and why that matters

PoSv3 block validity hinges on the **stake kernel**: hash(stake modifier,
prevout's block time, prevout, block time) < target x stake amount, with
the staked UTXO existing, being mature (500 conf) and unspent. The amount,
age and unspentness live in the UTXO set, not in headers. Consequences:

- A header-only client accepts any header chain with plausible shape. An
  attacker who *once* controlled old UTXOs (even long since spent) can
  fabricate an alternative history from that point — the classic
  **long-range / costless simulation** attack on PoS light clients.
- Runebase (like Qtum, like Bitcoin) has **probabilistic finality**; IBC's
  client semantics explicitly permit this via "thresholding views"
  (ICS-002): treat a block as final after N confirmations. But a threshold
  only defends against short reorgs, not fabricated histories.

### The three honest mitigation levels

1. **Weak subjectivity (pragmatic, deployable):** the Wasm client embeds a
   recent checkpoint at creation and refuses reorgs deeper than a bounded
   window W (2000 blocks ≈ 17.8h — **confirmed from source**: this is
   exactly the window Runebase nodes themselves enforce via `CheckSync`,
   and `nRBTCheckpointSpan` is literally defined as
   `nRBTCoinbaseMaturity`; see
   [../long-range-attacks.md](../long-range-attacks.md) §2.1). Within
   W, fabricating a competing chain requires currently-staked coins and
   sacrifices real staking rewards — an economic, quantifiable defense.
   Checkpoint refresh happens implicitly as the client follows the chain;
   only a client offline longer than W needs re-initialization (a
   counterparty governance action, same as Tendermint clients recovering
   from unbonding-period expiry). Trust added: the *initial* checkpoint,
   verifiable by anyone against the public chain.
2. **Extended proofs (stronger, more work):** alongside each header,
   relay a Merkle proof (against an earlier header's tx-merkle-root) that
   the staking prevout was created with the claimed amount and age. This
   lets the client verify the kernel equation itself, closing the "invented
   stake" hole; only *double-staking an already-spent output* remains,
   which the depth window covers. Requires a proof-serving RPC on the node
   (below) and a bespoke client — no precedent to copy, medium research
   risk.
3. **zk full validation (endgame):** an SP1-style program that runs actual
   Runebase contextual validation (headers + kernel + UTXO updates) and
   emits a Groth16 proof the Cosmos side verifies. Everything needed is
   open-source precedent *in shape* (Eureka does exactly this for
   Tendermint) but nobody has written it for a UTXO-PoS chain; treat as a
   funded research project, not a roadmap item.

### Node-side additions (non-consensus, needed for any outbound design)

| addition | purpose | size |
|---|---|---|
| `getstateproof` RPC (eth_getProof equivalent: account + storage MPT proof at a height) | proving packet commitments | medium; verified 2026-08-25 that `GenericTrieDB` has **no existing proof-extraction code** — the Merkle-branch walk is written from scratch against the stored trie |
| `getheaderchain` RPC (batch headers + optional prevout-inclusion proofs) | feeding the Wasm client | small |
| archival state retention flag | serving proofs for non-tip heights | config only; state DB already persists tries |

## Effort and sequencing

| phase | scope | estimate |
|---|---|---|
| 1 | Deploy Eureka Solidity stack on testnet, SP1 prover, relayer; Cosmos testnet -> Runebase transfers | 1-2 engineer-quarters, mostly integration |
| 2 | `getstateproof` + header RPCs on the node | weeks |
| 3 | 08-wasm Runebase client, level-1 security (weak subjectivity + threshold) | 1-2 quarters incl. audit |
| 4 | Level-2 extended proofs; level-3 zk client | research track |

**Bottom line:** IBC is the right target architecture — permissionless
relayers by design, production Solidity implementation, and our EVM already
carries the exact precompiles its verifiers use. Commit to it with eyes
open: the outbound client's security level must be explicitly chosen and
documented, because "IBC" alone does not answer how a remote chain learns
to trust a UTXO-PoS header.
