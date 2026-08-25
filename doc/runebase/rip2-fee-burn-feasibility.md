# RIP-2 feasibility — burning all transaction and gas fees

Research date: 2026-08-25, against v29.1.0 (post-Pectra/RIP-1 codebase).
Proposal: keep the 25 RUNES block subsidy, but destroy all consumed
transaction fees and gas fees instead of paying them to the staker.
This document answers: is it feasible, what exactly changes, what breaks,
and what the design decisions are.

**Verdict: highly feasible, and structurally simpler than RIP-1 was.**
The UTXO model does most of the work for free. The engineering is small
and localized; the open questions are economic (staker incentives), not
technical.

## 1. How fees flow today (verified in source)

A fee in a UTXO chain is not a payment to anyone — it is the *gap*
between a transaction's inputs and outputs. It only becomes someone's
money when the block producer claims it in the coinstake. The entire
claiming mechanism is:

- **Consensus ceiling** — `CheckReward()`, `src/validation.cpp:3017/3026`:
  `blockReward = nFees + GetBlockSubsidy(...)`; the coinstake may pay out
  at most this. Gas refunds are carved out of the same pot
  (`blockReward - gasRefunds` is what recipients split, `:3047`), and the
  refund outputs themselves are *enforced to exist* separately
  ("bad-gas-refund-missing", `:3007`). An invariant `nFees >= gasRefunds`
  is checked at `:4115`.
- **Producer side** — `src/wallet/stake.cpp:225`
  (`nReward = nTotalFees + GetBlockSubsidy(...)`), fed from
  `src/node/miner.cpp:326` where `pTotalFees = nFees - refundSender`,
  i.e. the staker claims **consumed** fees (refunded gas already
  excluded). The PoW-era coinbase path (`miner.cpp:258/404`) does the
  same; on mainnet it is history (PoW ended at block 5000) but regtest
  still exercises it.
- **Supply accounting** — `src/validation.cpp:4213`:
  `nMoneySupply = prev + nValueOut - nValueIn` summed over the whole
  block.
- **Delegation / super-staking** — splits `nReward` by the delegation
  fee percentage (`stake.cpp`, `CreateCoinStakeFromDelegate`); MPoS
  splitting ended at mainnet block 899999 and is irrelevant at any
  future fork height.

Notably, the consensus check is an **upper bound** (`>` at `:3027`).
Claiming *less* than fees+subsidy is already valid today — a staker can
voluntarily burn fees under current rules. RIP-2 is therefore a
*tightening* of an existing bound, not a new mechanism.

## 2. The change, precisely

From activation height (call it `nRIP2Height`, riding the same pattern
as RIP-1):

```
CheckReward:   blockReward = gasRefunds + GetBlockSubsidy(...)   // was: nFees + subsidy
stake.cpp:     nReward     = GetBlockSubsidy(...)                // was: nTotalFees + subsidy
miner.cpp:     coinbase    = GetBlockSubsidy(...)                // PoW branch, regtest only
```

Gas refunds keep flowing exactly as today: the refund vouts remain
mandatory, they remain funded by the block's fee pool, and the
`nFees >= gasRefunds` invariant at `:4115` remains valid unchanged. The
staker's net income becomes the subsidy alone; consumed fees never enter
any output and are thereby destroyed.

### What needs NO change — and why this design is clean

- **Supply tracking: zero changes.** Because `nMoneySupply` is computed
  as `sum(valueOut) - sum(valueIn)` over the block
  (`validation.cpp:4213`), unclaimed fees *automatically* decrement
  supply. `getblockchaininfo.moneysupply` becomes an honest
  net-of-burn figure with no new code. Cumulative burn is derivable as
  `sum(subsidies) - moneysupply` (a convenience `getburninfo` RPC is a
  nice-to-have, not a requirement).
- **Users and wallets: zero changes.** Fees are paid identically;
  only the claiming side changes. Fee estimation, mempool policy,
  RBF, P2P relay — all untouched.
- **The EVM, RIP-1, DGP: zero changes.** Gas pricing and refund
  mechanics are orthogonal to who receives (or doesn't receive) the
  consumed portion.
- **The inflation guard** (`:4217`) is an upper bound and stays valid.
- **Delegation contract: zero changes.** The split percentage now
  applies to a subsidy-only reward; the contract never knew about fees.

## 3. Deployment character: a rule-tightening, like RIP-1

Post-fork blocks (claiming subsidy only) are **valid under the old
rules too** — old nodes follow the new chain. The split risk is
one-directional: a *staker* on old software will eventually claim fees
and produce a block new nodes reject with `bad-cs-amount`. Identical
messaging to RIP-1 applies: every staker must upgrade before the
height; non-staking old nodes degrade gracefully rather than forking
off immediately. This is the mildest hardfork class available.

## 4. Economics — the real decision surface

Current numbers (mainnet, ~32s blocks, ~2700 blocks/day):

- Issuance: 25 RUNES/block ≈ 67,500/day ≈ 24.6M/year (~11.8% of the
  ~208M supply).
- Today's blocks are mostly empty: burning fees costs stakers almost
  nothing *now* and burns almost nothing *now*. The mechanism matters
  exactly in proportion to future usage — which is the point.
- Post-RIP-1 burn rates when usage arrives: a standard send burns
  ~0.15 RUNES; a 100k-gas contract call burns ~4 RUNES; a heavy 1M-gas
  call burns ~40. Net deflation begins when a block's fees exceed
  25 RUNES — roughly six mid-size contract calls per block.
- Synergy with RIP-1 is real: RIP-1 set a consensus floor on gas
  prices; RIP-2 would redirect that floor's proceeds from stakers to
  everyone (via supply reduction). Spam still costs the attacker the
  same; it just enriches no one.

### The one genuine problem: the empty-block incentive

If stakers earn *nothing* from including transactions, the rational
staker includes none — inclusion costs validation time and (slightly)
raises orphan risk, and pays zero. Ethereum hit exactly this in
EIP-1559's design and answered it by burning only the *base* fee while
keeping a priority tip for the producer. Options, honestly ranked:

1. **Full burn (as proposed).** Simplest consensus, cleanest story.
   Risk: relies on staker altruism/software-defaults for inclusion.
   Mitigating realities: our default software includes transactions
   (laziness requires deliberately patching the node), blocks are 32s
   apart so backlog pressure is visible fast, and today's fee volumes
   make the forgone income ~zero. Danger grows precisely when the
   chain succeeds.
2. **Floor-burn + tip (EIP-1559-shaped).** Burn the consensus-known
   floor (min gas price x gasUsed for contract calls, plus a
   *consensus-ified* minimum feerate for plain bytes), staker keeps
   any excess above the floor as a tip. Preserves the inclusion
   incentive forever. Cost: the minimum relay feerate is today a
   *policy* value (`DEFAULT_MIN_RELAY_TX_FEE`); consensus code must
   never reference policy, so RIP-2 would have to promote a minimum
   feerate into consensus params — a bigger, subtler change than
   option 1, and a second knob to govern.
3. **Percentage burn.** Burn X% of fees. No new consensus inputs
   needed (percentage of an already-computed quantity), keeps partial
   incentive. Less principled than 2, simpler than 2, weaker burn
   than 1.

**Recommendation:** if the goal is the strongest possible monetary
story and simplest consensus, option 1 is defensible *today* given
empty blocks — but commit in advance to the option-2 escape hatch
(the fork machinery is identical; only the formula differs) if
empty-block behaviour ever appears. If the goal is never having to
revisit it, pay the complexity of option 2 once, now.

## 5. Side benefits worth stating

- **Fee sniping dies.** Reorging to steal a fee-rich block becomes
  pointless when fees are unclaimable — a small but real consolidation
  of PoS security, and it removes the classic incentive anomaly of
  high-fee blocks.
- **MEV-adjacent pressure drops** for the same reason (though ordering
  games inside a block remain).
- Deflation accounting is externally auditable from headers + supply
  alone — explorers need no new indexes.

## 6. Implementation plan (mirrors RIP-1 exactly)

| piece | file | size |
|---|---|---|
| `nRIP2Height` consensus param | `consensus/params.h`, `kernel/chainparams.cpp` (per network; regtest `0x7fffffff` + `-rip2height` arg) | small |
| ceiling change | `CheckReward()` gate on height | ~5 lines |
| producer change | `stake.cpp` / `miner.cpp` gate on height | ~10 lines |
| functional test | `runebase_rip2_fee_burn.py`: pre-fork fee claim valid; post-fork claiming block rejected `bad-cs-amount`; subsidy-only block accepted; refunds still enforced; `moneysupply` decreases by burned amount; `-reindex` across the boundary | mirrors `runebase_rip1_gas_price.py` |
| docs/verify | CLAUDE.md + `verify-runebase-values.sh` entries | small |

Estimated effort: days for the consensus change, the test is the bulk.
Suggested activation: bundle with a scheduled upgrade window, not with
another consensus change — unlike RIP-1/Pectra, nothing forces
co-activation, and isolating it simplifies rollback messaging.

## 7. Risks and rebase burden

- **`CheckReward` becomes Runebase-specific.** Until now that function
  had *zero* delta from Qtum (deliberately — take upstream's version on
  every rebase). RIP-2 ends that: the delta must be re-applied on every
  future Qtum rebase, exactly like the RIP-1 gate in `getMinGasPrice`.
  This is the single largest ongoing cost of the proposal and must be
  recorded in CLAUDE.md the day it is implemented.
- **Staker revenue policy is one-way in practice.** Un-burning later
  (restoring fee income) would be a *loosening* fork — old nodes would
  reject fee-claiming blocks — the harder deployment direction. Treat
  the decision as permanent.
- Option 2's consensus-ified feerate, if chosen, adds a governance
  surface (who moves the floor?) — the DGP pattern exists for exactly
  this, but it is another moving part.
