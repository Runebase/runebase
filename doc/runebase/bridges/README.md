# Bridging options for Runebase — overview and comparison

Research date: 2026-08-25, against the v29.1.0 codebase (Pectra + RIP-1).
Constraint set by the project: **no option may require trusting relayers or
any centralized operator set**. Security ranks above convenience, cost and
time-to-market.

## The two directions are not equally hard

Every bridge decomposes into two independent problems, and on Runebase they
have very different difficulty:

**Inbound (other chain -> Runebase): engineering-grade, feasible today.**
A bridge contract on Runebase must verify the *counterparty's* consensus.
Runebase's EVM ships every cryptographic primitive the modern designs need,
verified live on this chain during the v29.1 work:

| primitive | precompile | active since | bridge use |
|---|---|---|---|
| alt_bn128 add/mul/pairing | 0x06-0x08 | genesis (Byzantium) | **Groth16 SNARK verification** — the exact scheme IBC Eureka uses on Ethereum (~230k gas/verification) |
| BLS12-381 suite | 0x0b-0x11 | Pectra fork | **native verification of BLS-signed consensus** (Ethereum sync committee, CometBLS) |
| sha256 / ripemd160 / blake2 | 0x02/0x03/0x09 | genesis / Istanbul | Merkle proofs, HTLCs, SSZ hashing |
| modexp | 0x05 | genesis | RSA-style and auxiliary verification |
| point_evaluation (KZG) | 0x0a | Cancun fork | EIP-4844-style data proofs |
| btc_ecrecover | 0x85 | genesis (QIP6) | Bitcoin-signed message verification |
| historical block hashes | EIP-2935 addr | Pectra fork | deep re-org checks inside contracts |

Block gas limit is 40M (DGP-governed), max contract size 24,576 bytes
(EIP-170) — both sufficient for every verifier discussed here. Inbound
designs need **zero consensus changes**: they are ordinary contracts plus
permissionless message carriers.

**Outbound (Runebase -> other chain): the hard problem.**
The counterparty must verify *Runebase's* consensus. Runebase is UTXO
proof-of-stake (Qtum PoSv3 lineage): block validity depends on a stake
kernel check against the spender's UTXO — data that lives outside the
header. A remote light client can validate the header *chain shape*
(difficulty retarget, signatures, timestamps, the 181-byte header layout)
but cannot, from headers alone, know whether the staked output existed,
was mature, and was unspent. This creates a long-range / costless-simulation
surface that every outbound design must answer. The three honest answers,
in increasing order of trustlessness, are analysed in each document:

1. confirmation-depth thresholding + weak-subjectivity checkpoints,
2. extended proofs (header + Merkle proof of the staking prevout),
3. a zk proof of full Runebase validation (research-grade).

One codebase fact makes all outbound designs *possible at all*: **every
Runebase header commits to the EVM state root** (`hashStateRoot`,
`src/primitives/block.h:31`). Once a counterparty accepts a header, a
standard Ethereum-style Merkle-Patricia storage proof reaches any contract
slot. The node is missing an `eth_getProof`-equivalent RPC to *serve* such
proofs — a small, non-consensus addition listed in every option's
requirements.

## The options

| # | option | trust model | consensus changes | works today? | doc |
|---|---|---|---|---|---|
| 1 | HTLC atomic swaps | none at all | none | **yes** | [01-htlc-atomic-swaps.md](01-htlc-atomic-swaps.md) |
| 2 | IBC (Eureka / ibc-solidity) | light client + permissionless relayers | none (inbound) | inbound: near-term; outbound: hard | [02-ibc.md](02-ibc.md) |
| 3 | zk light-client bridge (Ethereum) | light client + permissionless provers | none (inbound) | inbound: near-term; outbound: research | [03-zk-light-client.md](03-zk-light-client.md) |
| 4 | Optimistic (fraud-proof) bridge | 1-of-N honest watcher | none | mid-term | [04-optimistic-bridge.md](04-optimistic-bridge.md) |

## Rejected up front (fail the trust constraint)

- **Wormhole-style guardian sets, Axelar-style external validator sets** —
  a fixed committee signs state; compromise the committee, mint infinite
  wrapped supply. This is exactly the "relayer hijack" class excluded.
- **LayerZero default configuration** — security reduces to non-collusion
  of an oracle and a relayer chosen by the application; configurable, but
  the trustless configurations reduce to options 2/3 above anyway.
- **Multisig/threshold-custody wrapped assets (WBTC model, early tBTC)** —
  custodial by construction.
- **Notary/exchange bridges** — custodial by construction.

## Recommended sequencing (security first)

1. **Now:** HTLC atomic swaps (doc 01). Zero new trust, zero consensus risk,
   uses only what v29.1.0 already ships. Limited UX, but real utility and
   a forcing function to build the node-side proof RPC and indexing that
   every later option needs.
2. **Next:** inbound legs of IBC (doc 02) or the Ethereum zk bridge
   (doc 03) — both are contract deployments plus permissionless relaying,
   with the Groth16 verifier runnable on today's chain and the BLS path
   opening at the Pectra fork.
3. **Then:** the outbound problem, deliberately: implement the
   confirmation-threshold client with published weak-subjectivity
   checkpoints, and treat the zk-full-validation client as the long-term
   destination.
