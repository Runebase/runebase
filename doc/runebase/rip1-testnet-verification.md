# RIP-1 testnet verification — smart contract + delegation, before and after the fork

RIP-1 raises the minimum EVM gas price 100x (40 -> 4000 satoshi/gas) at
`nRIP1Height` = **190000** on testnet (bundled with Pectra). This is the manual
run-through to prove the fork on the live testnet. Run every "BEFORE" step at a
height comfortably below 190000, and every "AFTER" step once the chain is past
it. Keep the txids; they are the evidence.

Conventions: `CLI` = `runebase-cli -testnet`. Amounts in RUNES.

## 0. Sanity

    CLI getblockcount
    CLI getdgpinfo          # BEFORE: "mingasprice": 40      AFTER: 4000

## 1. Deploy a test contract (BEFORE the fork)

A minimal counter contract (inc() = 371303c0, counter() = 61bc221a):

    CLI createcontract 6060604052341561000c57fe5b5b61011e8061001c6000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806312065fe0146058578063371303c014607b57806361bc221a14608a578063d0e30db01460ad575bfe5b3415605f57fe5b606560b5565b6040518082815260200191505060405180910390f35b3415608257fe5b608860d5565b005b3415609157fe5b609760e9565b6040518082815260200191505060405180910390f35b60b360ef565b005b60003073ffffffffffffffffffffffffffffffffffffffff163190505b90565b60016000600082825401925050819055505b565b60005481565b5b5600a165627a7a72305820fe93d8cc66557a2a6c8347f481f6d334402a7f90f8b2288668a874c34416a4dc0029

Save the returned `address` as `$C`. Wait for a confirmation.

## 2. BEFORE the fork (height < 190000)

    # a) call at the old minimum gas price -> must confirm
    CLI sendtocontract $C 371303c0 0 100000 0.00000040
    # after 1 confirmation:
    CLI callcontract $C 61bc221a      # executionResult.output increments

    # b) delegation at the old prices -> must verify
    STAKER=$(CLI getnewaddress "" legacy)
    DELEGATOR=$(CLI getnewaddress "" legacy)
    CLI sendtoaddress $DELEGATOR 10           # covers ~0.9 gas + fees at 40
    # after 1 confirmation:
    CLI setdelegateforaddress $STAKER 10 $DELEGATOR
    # after 1 confirmation:
    CLI getdelegationinfoforaddress $DELEGATOR    # "verified": true

## 3. AFTER the fork (height >= 190000)

    CLI getdgpinfo                                # "mingasprice": 4000

    # a) the old price must now be REJECTED (wallet-side error):
    CLI sendtocontract $C 371303c0 0 100000 0.00000040
    #   -> error: Invalid value for gasPrice (Minimum is: 0.00004000)

    # b) the new price must work:
    CLI sendtocontract $C 371303c0 0 100000 0.00004000
    # after 1 confirmation:
    CLI callcontract $C 61bc221a                  # output incremented again

    # c) wallet defaults follow automatically (no explicit gas price):
    CLI sendtocontract $C 371303c0
    CLI gettransactionreceipt <txid>              # confirms with gasUsed > 0

    # d) delegation still round-trips at the new prices.
    #    NOTE the cost: default delegation gas limit ~2.25M x 4000 sat ~= 90 RUNES,
    #    so fund the delegator accordingly:
    CLI removedelegationforaddress $DELEGATOR
    # after 1 confirmation:
    CLI sendtoaddress $DELEGATOR 200
    # after 1 confirmation:
    CLI setdelegateforaddress $STAKER 10 $DELEGATOR
    # after 1 confirmation:
    CLI getdelegationinfoforaddress $DELEGATOR    # "verified": true again

## 4. The no-stall proof

On a SEPARATE machine (or datadir), sync a fresh node from scratch AFTER the
fork height has passed:

    runebased -testnet -datadir=/tmp/rip1sync -printtoconsole

It must cross 190000 without `bad-tx-low-gas-price` errors and reach the
network tip. Optionally also `-reindex` an existing node. Either reproduces
what every future IBD will do: validate pre-fork blocks at 40 and post-fork
blocks at 4000.

## 5. What a failure looks like

- Chain stalls at 190000 with `bad-tx-low-gas-price` -> the height gate is
  broken (validating old blocks with the new minimum).
- `sendtocontract` fails with "Maximum allowed in RPC calls" after the fork ->
  `MAX_RPC_GAS_PRICE` was not scaled (must be 0.0001).
- Old nodes (pre-RIP-1 binaries) continuing past 190000 accept 40-priced
  transactions and will fork off — that is expected hardfork behaviour, not a
  bug.
