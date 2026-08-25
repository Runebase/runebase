# DEX feasibility on Runebase — options, security, sequencing

Research date: 2026-08-25, against v29.1.0 (post-Pectra/RIP-1). Companion to
`doc/runebase/bridges/` — but note up front: **a DEX does not have to wait
for a bridge.** RUNES/RRC-20 pairs trade with zero external dependencies;
bridged assets (wrapped ETH, stables) extend an existing DEX rather than
gate it.

## 1. What the chain verifiably supports

From the bridge research's live regtest battery (2026-08-25) and this tree:

| requirement | status |
|---|---|
| Solidity 0.5-0.8.x bytecode, `cancun` target | **verified live** — PUSH0, TSTORE/TLOAD, MCOPY executed on-chain |
| CREATE2 (deterministic pool addresses) | upstream evmone, standard semantics |
| payable contracts holding/sending native value | exercised daily by the delegation contract and the EVM functional test suite |
| keccak256, ecrecover (permit/EIP-2612 signatures) | genesis precompiles |
| event logs + indexing | `-logevents` RPCs (`searchlogs`, `gettransactionreceipt`, `getblocktransactionreceipts`) — live-tested during the explorer work |
| 24,576-byte contract size limit (EIP-170) | standard — all Uniswap-family contracts fit (they deploy on Ethereum) |

**The one Runebase-specific EVM rule that matters:**
`CREATE`/`CREATE2` with a value endowment is consensus-banned
(`EVMC_CREATE_WITH_VALUE`, `src/evmone/lib/evmone/instructions_calls.cpp:345`).
Audited against the Uniswap family: v2 `createPair`, v3 pool deployment and
the v4 singleton all deploy with **zero value** — unaffected. But this is a
mandatory audit line-item for *any* ported DeFi suite (some vault/escrow
factories instantiate children with value; on Runebase they revert).

A wrapped-native contract (**WRUNES**, the WETH9 pattern) is the one
universal prerequisite — trivial, ancient solc, deploy once, never touch
again.

## 2. The options

### 2a. Uniswap v2 fork — constant product AMM

- **License:** GPL-3.0 — freely forkable, always was.
- **Track record:** the most battle-tested DeFi contract in existence
  (2020-present, uncountable forks). The audit surface is essentially
  closed; remaining risk is *fork-introduced* error, not design error.
- **Complexity:** core is ~700 lines. Passive LPing, no position NFTs, no
  tick math. Indexing needs are minimal (Sync/Swap events).
- **Gas under RIP-1:** swap ~110k gas ≈ **4.4 RUNES minimum**; add/remove
  liquidity ~150k ≈ 6 RUNES. (All figures at the 4000 sat/gas floor.)
- **Fit:** the obvious first DEX. Works today with RUNES + RRC-20 pairs.

### 2b. Uniswap v3 fork — concentrated liquidity

- **License:** BUSL expired April 2023 → GPL-2.0-or-later. Freely forkable.
- **Track record:** excellent since 2021; complexity an order of magnitude
  above v2 (tick math, position NFTs, multiple fee tiers).
- **Gas:** swap ~130k ≈ 5.2 RUNES.
- **Operational reality check:** concentrated liquidity assumes *active*
  LPs and rich indexing/UI (positions, ranges, fee accounting). On a chain
  bootstrapping liquidity, v3's capital efficiency mostly rewards
  sophisticated LPs who are not there yet, while tripling the integration
  and support burden. Better as a second-generation upgrade.

### 2c. Uniswap v4 — singleton + hooks

- **License:** BUSL until **June 15, 2027**, then MIT
  ([Uniswap Labs](https://support.uniswap.org/hc/en-us/articles/33829751588109-Uniswap-v4-licensing)).
  Production deployment before then requires a governance-granted
  exemption — realistically not worth pursuing.
- **Technically notable:** v4 *requires* transient storage (EIP-1153,
  Cancun) — and Runebase is one of the few non-Ethereum-L2 chains where
  that requirement is **verified working** (our TSTORE/TLOAD live test).
  When the license flips in mid-2027, Runebase can host it.
- **Verdict:** revisit in 2027; not before.

### 2d. Solidly / ve(3,3) family (Velodrome-style)

Emissions-directed AMMs. They solve liquidity *incentive* problems by
adding a token-emissions political layer — governance, gauges, bribes.
High operational complexity, mixed security history in forks, and the
mechanism presumes an emissions budget Runebase's fixed 25-RUNES subsidy
does not naturally provide (and RIP-2, if adopted, moves the monetary
story the opposite direction). **Not recommended.**

### 2e. Curve-style stableswap

Only meaningful once bridged stables exist (see bridges doc). Vyper
compiles to ordinary EVM bytecode, so hosting is unproblematic. Sequence
strictly after the bridge; pair it with whatever AMM is already live.

### 2f. On-chain order book (CLOB)

Rejected on arithmetic: order placement/cancellation are storage-heavy
transactions, and RIP-1's 4000 sat/gas floor exists precisely to make
state growth expensive. A CLOB fights the chain's own economic design.

### 2g. Intent/RFQ systems (CoW-style)

Off-chain solvers, on-chain settlement. Interesting *later* as an overlay
above an AMM (solvers need somewhere to route), meaningless as a first
venue. Requires solver infrastructure nobody will run for a small chain.

## 3. Runebase-specific security analysis

**Oracle manipulation is the #1 risk to plan around.** There is no
Chainlink on Runebase and none is coming soon — whatever DEX deploys
becomes the chain's de-facto price oracle, and early pools will be
shallow:

- v2 spot prices are trivially manipulable in thin pools; anything that
  *consumes* prices (future lending, liquidations) must use long-window
  TWAPs, never spot.
- Block cadence helps and hurts: 32s blocks (timestamp mask forces 16s
  granularity) mean a TWAP window of N seconds spans fewer observations
  than on Ethereum; use longer windows (hours, not minutes).
- A single staker who wins consecutive blocks can place manipulation +
  victim transactions adjacently at zero mempool exposure. PoS makes
  this probabilistic, not impossible. Consequence: **do not build
  price-consuming protocols on day-one liquidity**; the DEX itself is
  safe (LPs and traders bear only their own slippage), it is the
  *downstream consumers* that get hurt.

**MEV/sandwiching exists here like everywhere.** Public mempool, staker
ordering, no PBS/flashbots infrastructure. Mitigations available now:
tight slippage defaults in the UI and the RIP-1 floor itself (a sandwich
costs ≥ ~9 RUNES of burned-or-paid gas for two transactions, a real
deterrent at small trade sizes). Document, don't promise elimination.

**Fork-engineering pitfalls (the classic ways v2 forks get burned):**

- **INIT_CODE_HASH:** the periphery router computes pair addresses from a
  hardcoded hash of the pair contract's creation bytecode. Recompiling
  the core with any change (even metadata) changes the hash; a mismatch
  silently routes to empty addresses. Recompute and test on regtest —
  our functional-test framework already deploys and calls contracts, so
  an automated check is cheap.
- **RRC-20 non-standard tokens:** RRC-20 is interface-identical to ERC-20
  (rebrand only), but the ecosystem will contain missing-return-value
  and fee-on-transfer tokens like every chain's does. Keep v2's
  `swap*SupportingFeeOnTransferTokens` paths and safe-transfer wrappers
  exactly as upstream ships them.
- **Admin surface:** v2's only privileged knob is `feeTo`/`feeToSetter`
  (protocol fee switch). Put it behind a timelock from day one; publish
  the address. Resist adding pausability — it converts a trustless venue
  into a custodial-adjacent one and is the single most common
  fork-added vulnerability.
- **RIP-2 interplay (if adopted):** with fees burned, every swap's ~4.4
  RUNES of gas is destroyed — DEX volume becomes a direct deflation
  engine. No code impact; worth stating in the economics narrative.

## 4. The actual critical path: not the contracts

The AMM contracts are the *easy* 10%. What determines whether a Runebase
DEX exists in practice:

1. **Web wallet / RPC adapter.** ethers.js/viem frontends speak
   `eth_*` JSON-RPC and expect secp256k1 EVM accounts. runebased speaks
   Bitcoin-style RPC with UTXO-backed EVM transactions (OP_CALL via the
   wallet). The Qtum ecosystem bridges this with **Janus** (an
   ETH-JSONRPC-to-Qtum adapter) plus a browser wallet; Runebase has no
   maintained equivalent in this repo. Building/forking that adapter and
   one browser wallet integration is the **largest work item in the
   entire DEX project** and should start first.
2. **Indexer.** Pairs/prices/volume UI needs an event indexer. The
   `-logevents` RPC family (verified in the explorer research) is
   sufficient input; a small custom indexer beats porting The Graph.
3. **Liquidity bootstrapping.** A DEX with no liquidity is a manipulation
   honeypot (see §3). Seed RUNES/core-RRC-20 pools meaningfully before
   public launch, or launch is worse than not launching.

## 5. Recommendation

**Uniswap v2 fork, unmodified core, timelocked admin, WRUNES, launched
with seeded liquidity — preceded by the wallet-adapter work.**

Sequencing:

| phase | what | depends on |
|---|---|---|
| 1 | Janus-equivalent RPC adapter + browser wallet path | nothing — start now |
| 2 | WRUNES + v2 core/periphery on testnet, INIT_CODE_HASH regtest check, indexer | phase 1 for UI testing |
| 3 | Mainnet with seeded RUNES/RRC-20 pools, timelocked `feeToSetter` | phase 2 |
| 4 | Stableswap pool for bridged stables | the bridge (separate doc) |
| 5 | v3 (capital efficiency) when LP sophistication warrants; v4 when BUSL expires June 2027 | market maturity |

Security-first rationale: v2 is the only option whose *entire* failure
catalogue is public and closed; every alternative adds surface (v3
complexity, v4 license+hooks, ve(3,3) governance economics) before the
chain has the liquidity depth to justify it. The genuinely novel risks on
Runebase are environmental — thin-liquidity oracles and the missing
wallet layer — and both are addressed by sequencing, not by contract
choice.
