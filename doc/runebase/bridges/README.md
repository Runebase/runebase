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

**Read [../long-range-attacks.md](../long-range-attacks.md) before
designing any outbound client.** It quantifies this surface against the
live chain and establishes the one fact every outbound design depends
on: Runebase nodes enforce a **hard 2000-block (~17.8 h) max-reorg rule**
(`CheckSync`, `src/node/blockstorage.cpp:1067`), so a remote client that
mirrors it reaches full-node-equivalent security — provided its view
never goes stale. It also sets the HTLC timelock floor for option 1 and
the sizing bound for value locked outbound.

One codebase fact makes all outbound designs *possible at all*: **every
Runebase header commits to the EVM state root** (`hashStateRoot`,
`src/primitives/block.h:31`). Once a counterparty accepts a header, a
standard Ethereum-style Merkle-Patricia storage proof reaches any contract
slot. The node is missing an `eth_getProof`-equivalent RPC to *serve* such
proofs — a small, non-consensus addition listed in every option's
requirements.

## Verified against the codebase (regtest, v29.1.0, 2026-08-25)

The claims above are not read off a feature list — they were exercised on a
live regtest node of this tree. Test vectors for the curves were extracted
from the in-tree `src/blst` sources, and precompiles were reached through
deployed forwarder contracts (the `callcontract` RPC refuses direct calls
to accounts with no state, which precompiles are).

| check | method | result |
|---|---|---|
| modern Solidity output runs (PUSH0, TSTORE/TLOAD, MCOPY — solc 0.8.25+ `cancun` target, what current bridge stacks ship) | hand-assembled bytecode using all four opcodes, deployed and executed | **PASS** — returned expected value through transient storage + mcopy |
| BN254 `alt_bn128` computes (Groth16 substrate) | G1 mul/add identities, then full bilinearity `e(P,Q)·e(-P,Q) = 1` through the pairing precompile | **PASS** — pairing returned 1 |
| BLS12-381 computes (sync-committee / CometBLS substrate) | G1 `gen + inf = gen` with the real generator, then bilinearity `e(G,H)·e(-G,H) = 1` | **PASS** — pairing returned 1 |
| script-layer HTLC prerequisites | `BIP65Height = 0`, `CSVHeight = 6048` in chainparams — CLTV/CSV long active on mainnet | confirmed in source |
| in-EVM reorg lookback for fraud proofs | EIP-2935 serves the last **8191 block hashes** (~3 days at 32s) | confirmed in `runebaseutils.cpp` |

Codebase constraints found during verification — these bind every option:

- **`CREATE`/`CREATE2` with value is consensus-banned in the EVM**
  (`EVMC_CREATE_WITH_VALUE`, a Runebase-specific patch in
  `src/evmone/lib/evmone/instructions_calls.cpp:345`). Any third-party
  bridge contract that instantiates a child contract while sending value
  (`new Escrow{value: v}()`) **reverts on Runebase**. Zero-value factory
  and proxy deployments (the normal pattern, used by the IBC Eureka stack)
  are unaffected — but this is a mandatory audit item when porting any
  foreign contract suite.
- **The state trie has no proof-extraction code** (`GenericTrieDB` in
  `src/eth_client/libdevcore/TrieDB.h` stores and walks, but cannot emit
  Merkle branches). The `getstateproof` RPC every outbound design needs is
  a from-scratch addition, not an exposure of existing code.
- The `callcontract` RPC cannot address precompiles directly ("Address
  does not exist") and rejects empty calldata — irrelevant on-chain
  (contract-to-precompile calls work, as the tests prove), but relayer
  tooling that probes via RPC must know it.

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
