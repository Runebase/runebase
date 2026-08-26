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

### Option 4 (added 2026-08-27) — burn the GAS FLOOR only. Recommended.

The obstacle to option 2 was that a minimum *transaction* feerate is a
policy value (`DEFAULT_MIN_RELAY_TX_FEE`) and consensus must not read
policy. But that obstacle **does not exist for gas**: the minimum gas
price is *already* a consensus value, supplied by the DGP contract and
gated by RIP-1 (`RunebaseDGP::getMinGasPrice(height)`). So scope the
burn to gas and the design problem disappears:

```
burned        = Σ over contract txs of  minGasPrice × gasUsed
blockReward   = nFees − burned + GetBlockSubsidy(...)
```

Everything needed is already computed in `ConnectBlock`. Per contract
transaction it has `gasUsed` (`validation.cpp:3211`) and `gasPrice`
(`:3234`), and it already aggregates the mirror-image quantity — the
refund `(gas − gasUsed) × gasPrice` into `resultBCE.refundSender`
(`:3237/3245`) — plus `resultBCE.usedGas` for gas units (`:3223/3236`).
Adding a `burnedGas` accumulator beside `refundSender` is a few lines in
code that already exists for exactly this shape of arithmetic.

Why this is the best available design for Runebase:

- **It burns precisely what RIP-1 created.** RIP-1's whole purpose was a
  100x consensus floor on gas to price out spam. Option 4 sends that
  floor's proceeds to nobody, which is the honest completion of RIP-1's
  argument: spam should cost the spammer without enriching anyone.
- **The inclusion incentive survives.** Anything above the floor — the
  whole of plain transaction fees, plus any gas premium — still pays the
  staker. There is always a positive marginal reason to include a
  transaction and to prioritise by fee.
- **No new governance surface.** Option 2 needed a consensus-ified
  feerate and someone to govern it. Here the DGP already governs
  `minGasPrice`, with `MAX_MIN_GAS_PRICE_DGP` bounding it and RIP-1
  flooring it. Nothing new to argue about.
- **It fails safe.** If gas usage never materialises, nothing is burned
  and nothing is broken; the chain behaves exactly as today.

Cost relative to option 1: `CheckReward` must be told the burned amount
(one more parameter, and `ConnectBlock` must pass it), and the staker
and miner paths must subtract the same quantity. Slightly more than
option 1's ~15 lines, far less than option 2's new consensus parameter.

### But the stated goal is BOTH transaction fees and gas fees

Option 4 alone burns only the gas side. To cover plain transaction fees
too — the original proposal — the question is what to do about the fact
that **transaction fees have no consensus-known floor**, while gas does.
`nFees` in `CheckReward` is the total of every fee in the block, and
consumed gas is derivable (`nFees` minus the refund the code already
computes), so both quantities are available; the issue is purely what
*fraction* to burn and how consensus knows it.

Three ways to include transaction fees, and only one needs no new
consensus input:

| | mechanism | new consensus input? | fee market |
|---|---|---|---|
| **4a** | burn gas floor + **X% of plain tx fees** | no — a constant | preserved (staker keeps 100−X%) |
| 4b | burn gas floor + **100% of tx fees** | no | plain-tx market unanchored |
| 4c | burn gas floor + tx fees above a **consensus feerate floor** | yes — promotes a policy value into consensus, plus governance | preserved |

**Recommended: 4a, with X high (90–95%).** Reasoning:

- It does what was actually asked — both fee types burn, the staker's
  income becomes the 25 RUNES subsidy plus a thin slice.
- The retained slice costs the burn almost nothing (5–10% of fees that
  are ~0 today) but buys a permanent property: **marginal revenue from
  including a higher-fee transaction stays positive**, so fee-based
  prioritisation remains economically real rather than merely a default
  in our software. Under congestion users can still bid.
- It needs no new consensus parameter and no governance surface. X is a
  constant next to `nRIP2Height`; it can be moved by a later fork, or
  wired into the DGP if that is ever wanted.
- Relative ordering — which is what actually drives block construction —
  is unaffected by any X < 100%.

**Why not 4b (burn everything).** The objection is not "stakers will
mine empty blocks": our default software includes transactions and the
mempool sorts by feerate regardless. The real harm is that a 100% burn
**unanchors the fee market** — with zero marginal revenue there is no
economic reason for any staker to prefer a higher-fee transaction, so
under congestion a user has no way to bid for inclusion. Runebase can
lean on the DGP to raise `maxblocksize` (500,000 on mainnet today)
instead of pricing congestion, but DGP changes need a governance round
trip, whereas a fee market clears automatically. Giving that up
permanently, in the harder-to-reverse fork direction, to gain 5–10% more
burn on fees that currently round to zero, is a poor trade.

**The one thing 4b buys** that 4a does not: fee sniping dies completely
rather than being reduced to a slice. Given the residual is proportional
to fees, that is a small gain for the cost above.

### Summary recommendation

1. **Burn 100% of the RIP-1 gas floor** (`minGasPrice × gasUsed`) —
   principled, precise, completes RIP-1's argument, no new governance.
2. **Burn 90–95% of everything else**, keeping a thin slice so the fee
   market stays anchored.
3. **Ship it on its own fork**, after RIP-1 has run on mainnet and after
   v30.2 lands. Nothing here is time-sensitive: with near-empty blocks
   the burn is ~0 today, and the whole design only starts to matter when
   Runebase has the usage that makes it worth having.

## 4b. The uncomfortable question: what is RIP-2 actually for?

Worth stating plainly before committing consensus changes, because the
answer shapes which option is right — and whether the timing is.

**If the goal is reducing inflation, RIP-2 is not the lever.** Measured
on mainnet 2026-08-27 at height 2,791,664:

| | |
|---|---|
| circulating supply | 208,041,425 RUNES |
| annual issuance (25 x ~2700 blocks/day) | 24,637,500 RUNES |
| **inflation rate** | **11.8% / year** |
| fees needed merely to *offset* issuance | 25 RUNES **per block, every block** |

25 RUNES/block is roughly six mid-size contract calls in every single
block, sustained. Runebase's blocks are near-empty today, so RIP-2 would
burn approximately nothing and change the 11.8% figure by approximately
nothing. **The subsidy is the inflation; fees are noise.** If the monetary
outcome is what matters, the honest lever is `GetBlockSubsidy` — a much
bigger conversation, and one this document explicitly does not make.

That is not an argument against RIP-2. It is an argument for being clear
that RIP-2 is a **structural** decision, not a monetary one: it decides
*where fee revenue goes if and when Runebase gets real usage*. Both its
benefit and its risk are deferred to the same future.

**The deeper risk with a full burn is not "stakers stop including".**
Default software includes transactions and the mempool already sorts by
feerate/gas price, so mechanically blocks keep filling. The subtler harm
is that a full burn **unanchors the fee market**: if no staker profits
from a higher fee, then under congestion a user has no way to bid for
inclusion, and nothing economically sustains fee-based prioritisation.
Option 4 preserves that anchor by construction.

**One honest point in favour of the full burn:** fee sniping (reorging
to capture a fee-rich block) is fully eliminated only if fees are wholly
unclaimable; option 4 leaves a residual proportional to tips. Given that
the residual is proportional to fees, and fees are ~0 today and bounded
by competition later, this is a small price for keeping the fee market
functional.

**Timing.** RIP-1 has not activated on mainnet yet (block 2,810,000,
~2026-09-02) and v30.2 is mid-flight. Stacking a second consensus change
onto an unproven one, in a codebase mid-rebase, is how avoidable
incidents happen. Ship RIP-1, let it run, finish v30.2, then schedule
RIP-2 on its own with its own testnet cycle. Nothing about RIP-2 is
time-sensitive — it only matters when usage arrives.

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
| burned-gas accumulator | `ConnectBlock`: sum `minGasPrice x gasUsed` per contract tx, beside the existing `refundSender` accumulator (`validation.cpp:3237/3245`) | ~10 lines |
| ceiling change | `CheckReward()` gate on height, minus the burned amount (new parameter) | ~10 lines |
| producer change | `stake.cpp` / `miner.cpp` gate on height, same subtraction | ~15 lines |
| functional test | `runebase_rip2_fee_burn.py`: pre-fork full fee claim valid; post-fork a block claiming the burned floor rejected `bad-cs-amount`; a correctly-reduced claim accepted; **gas premium above the floor still payable to the staker**; refunds still enforced; `moneysupply` decreases by exactly the burned amount; `-reindex` across the boundary reaches the same tip | mirrors `runebase_rip1_gas_price.py` |
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
