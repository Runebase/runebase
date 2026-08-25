# Option 1 — HTLC atomic swaps

**Trust model: none.** No relayers, no committees, no light clients. The
counterparty in a swap is the only other party involved, and the worst they
can do is waste your time until a timeout refunds you.

## How it works

A hash-time-locked contract locks funds under two conditions: reveal the
preimage of hash `H` before time `T`, or refund to sender after `T`. Two
such locks on two chains, sharing one `H` with staggered timeouts, make the
swap atomic: redeeming on one chain necessarily reveals the preimage that
unlocks the other.

## Why Runebase is unusually well suited

Runebase can host the lock on **either of its two layers**:

1. **UTXO script layer** — the same `OP_SHA256 <H> OP_EQUALVERIFY` /
   `OP_CHECKLOCKTIMEVERIFY` scripts Bitcoin uses. This makes Runebase
   swap-compatible with **Bitcoin, Litecoin and every Bitcoin-script chain**
   with no EVM involvement at all.
2. **EVM contract layer** — a standard Solidity HTLC (as used on
   Ethereum) makes Runebase swap-compatible with **every EVM chain**, and
   supports RRC-20 tokens, not just the native coin. `sha256` (0x02) and
   keccak are both available, so either hash convention works.

The same secret can bridge both conventions: a swap of BTC (script HTLC)
against an RRC-20 (EVM HTLC) works because both sides just need the same
preimage-of-sha256 condition.

Relevant codebase facts:
- CLTV active from genesis (`BIP65Height = 0`) and CSV from height 6048
  (`src/kernel/chainparams.cpp:104-106`) — both live on mainnet for years.
- EVM `block.timestamp`/`block.number` usable for the contract-side
  timeout; 32s blocks give fine-grained timeout control.
- The v29.1 fee corrections matter here: before them, the wallet's usable
  fee window (~2.5x min) made time-sensitive redemption transactions
  unreliable under load. Post-v29.1 the window is ~250x.

## Limitations (why this is the start, not the end)

- **Liquidity/UX**: swaps need a live counterparty with inverse intent.
  In practice this means an orderbook/coordination layer (an off-chain
  matcher — which touches no funds and therefore adds no custody trust).
- **No message passing**: swaps move value, not arbitrary data. No
  cross-chain contract calls.
- **Free-option problem**: the initiator can abort after seeing price
  movement; mitigated by short timeouts and reputation, not eliminated.
- **Online requirement**: the redeeming side must act before the timeout;
  watchtower services are optional and trustless (they can only help, not
  steal).

## What to build

| piece | effort | notes |
|---|---|---|
| Solidity HTLC contract (native + RRC-20) | small | audited templates exist (e.g. the classic `HashedTimelockERC20` pattern) |
| Script-layer HTLC support in the wallet (`sendtohtlc`, `redeemhtlc` RPCs) | medium | new wallet RPCs; no consensus change |
| Swap coordination daemon (orderbook + protocol messages) | medium-large | off-chain, holds no keys |
| RIP-1 awareness | trivial | redeem txs on the EVM side price gas at the post-fork 4000 sat/gas minimum |

Nothing here needs a hardfork, and nothing needs the outbound light-client
problem solved. This is the only option deliverable in weeks rather than
quarters, and shipping it exercises the exact wallet/node plumbing the
later options reuse.
