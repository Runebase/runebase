#!/usr/bin/env python3
# Copyright (c) 2026 The Runebase Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RIP-1, the 100x minimum gas price hardfork (nRIP1Height).

Runebase Improvement Proposal 1: "Gas Fee Adjustment to Prevent Spam and
Limit Blockchain Growth".

Runebase's transaction fees are 100x Qtum's, but the minimum EVM gas price
stayed at 40 satoshi/gas because raising it unconditionally would invalidate
historical blocks. The fork raises the default minimum to 4000 from
nRIP1Height (bundled with Pectra on mainnet/testnet), height-gated so
old blocks still validate.

This test proves, on one chain:
 BEFORE the fork:
 - wallet and raw contract calls work at the old minimum (40),
 - offline-staking delegation round-trips (setdelegateforaddress ->
   getdelegationinfoforaddress "verified": true),
 - a 40-priced call is accepted into the very last pre-fork block.
 AFTER the fork:
 - the old price 40 is rejected on BOTH paths (wallet: "Invalid value for
   gasPrice"; raw/mempool: "bad-tx-low-gas-price"),
 - wallet and raw contract calls work at the new minimum (4000),
 - contract creation with wallet-default gas price works (defaults follow the
   DGP automatically),
 - delegation still round-trips: remove, re-delegate, "verified": true again.
 AND ACROSS the boundary:
 - a full -reindex revalidates every block, old-priced and new-priced alike
   (the "will not stall / stays syncable" guarantee).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.runebase import *
from test_framework.runebaseconfig import COINBASE_MATURITY
from test_framework.script import CScriptNum

FORK_HEIGHT = 2200
OLD_MIN_GAS_PRICE = 40
NEW_MIN_GAS_PRICE = 4000  # 100x
COUNTER_INC = "371303c0"   # inc()
COUNTER_GET = "61bc221a"   # counter()
COUNTER_BYTECODE = "6060604052341561000c57fe5b5b61011e8061001c6000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806312065fe0146058578063371303c014607b57806361bc221a14608a578063d0e30db01460ad575bfe5b3415605f57fe5b606560b5565b6040518082815260200191505060405180910390f35b3415608257fe5b608860d5565b005b3415609157fe5b609760e9565b6040518082815260200191505060405180910390f35b60b360ef565b005b60003073ffffffffffffffffffffffffffffffffffffffff163190505b90565b60016000600082825401925050819055505b565b60005481565b5b5600a165627a7a72305820fe93d8cc66557a2a6c8347f481f6d334402a7f90f8b2288668a874c34416a4dc0029"


class RunebaseGasPriceForkTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-rip1height=%d' % FORK_HEIGHT, '-logevents', '-txindex']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to(self, height):
        n = height - self.node.getblockcount()
        assert n >= 0, "already past height %d" % height
        if n:
            self.generate(self.node, n)
        assert_equal(self.node.getblockcount(), height)

    def counter_value(self):
        out = self.node.callcontract(self.contract_address, COUNTER_GET)['executionResult']['output']
        return int(out, 16)

    def raw_call(self, gas_price, vin=None):
        """Build+sign a raw OP_CALL tx to the counter contract at the given gas price."""
        gas_limit = 100000
        if vin is None:
            # margin on top of the gas cost pays the (100x) relay fee
            vin = make_vin(self.node, gas_limit * gas_price + 60000000)
        outputs = [make_op_call_output(0, b"\x04", CScriptNum(gas_limit), CScriptNum(gas_price),
                                       bytes.fromhex(COUNTER_INC), bytes.fromhex(self.contract_address))]
        return make_transaction(self.node, [vin], outputs)

    def set_and_verify_delegation(self):
        txid = self.node.setdelegateforaddress(self.staker_address, 10, self.delegator_address)['txid']
        self.generate(self.node, 1)
        info = self.node.getdelegationinfoforaddress(self.delegator_address)
        assert_equal(info['staker'], self.staker_address)
        assert_equal(info['fee'], 10)
        assert_equal(info['verified'], True)
        return txid

    def run_test(self):
        self.node = self.nodes[0]

        self.log.info('Setting up: maturity + contract + funded delegator')
        self.generate(self.node, 100 + COINBASE_MATURITY)  # 2100
        self.contract_address = self.node.createcontract(COUNTER_BYTECODE)['address']
        self.staker_address = self.node.getnewaddress("", "legacy")
        self.delegator_address = self.node.getnewaddress("", "legacy")
        self.node.sendtoaddress(self.delegator_address, 300)
        self.generate(self.node, 1)

        self.log.info('PRE-FORK: dgp minimum is the old 40')
        assert_equal(self.node.getdgpinfo()['mingasprice'], OLD_MIN_GAS_PRICE)

        self.log.info('PRE-FORK: wallet contract call at 0.00000040 works')
        self.node.sendtocontract(self.contract_address, COUNTER_INC, 0, 100000, "0.00000040")
        self.generate(self.node, 1)
        assert_equal(self.counter_value(), 1)

        self.log.info('PRE-FORK: raw OP_CALL at gas price 40 works')
        self.node.sendrawtransaction(self.raw_call(OLD_MIN_GAS_PRICE))
        self.generate(self.node, 1)
        assert_equal(self.counter_value(), 2)

        self.log.info('PRE-FORK: offline-staking delegation round-trips (verified: true)')
        self.set_and_verify_delegation()

        # Prepare a funded input now; spent at the fork edge below.
        edge_vin = make_vin(self.node, 100000 * OLD_MIN_GAS_PRICE + 60000000)

        self.log.info('EDGE: a 40-priced call is still accepted into the last pre-fork block')
        self.mine_to(FORK_HEIGHT - 2)   # next block = FORK_HEIGHT-1, still pre-fork
        self.node.sendrawtransaction(self.raw_call(OLD_MIN_GAS_PRICE, vin=edge_vin))
        self.generate(self.node, 1)     # mined at FORK_HEIGHT-1
        assert_equal(self.node.getblockcount(), FORK_HEIGHT - 1)
        assert_equal(self.counter_value(), 3)

        self.log.info('FORK: crossing height %d' % FORK_HEIGHT)
        self.generate(self.node, 1)
        assert_equal(self.node.getblockcount(), FORK_HEIGHT)
        assert_equal(self.node.getdgpinfo()['mingasprice'], NEW_MIN_GAS_PRICE)

        self.log.info('POST-FORK: wallet rejects the old gas price')
        assert_raises_rpc_error(-3, "Invalid value for gasPrice",
                                self.node.sendtocontract, self.contract_address, COUNTER_INC, 0, 100000, "0.00000040")

        self.log.info('POST-FORK: mempool rejects a raw 40-priced call (bad-tx-low-gas-price)')
        assert_raises_rpc_error(-26, "bad-tx-low-gas-price",
                                self.node.sendrawtransaction, self.raw_call(OLD_MIN_GAS_PRICE))

        self.log.info('POST-FORK: raw call at the new minimum (4000) works')
        self.node.sendrawtransaction(self.raw_call(NEW_MIN_GAS_PRICE))
        self.generate(self.node, 1)
        assert_equal(self.counter_value(), 4)

        self.log.info('POST-FORK: wallet call at 0.00004000 works (RPC gas price cap was scaled too)')
        self.node.sendtocontract(self.contract_address, COUNTER_INC, 0, 100000, "0.00004000")
        self.generate(self.node, 1)
        assert_equal(self.counter_value(), 5)

        self.log.info('POST-FORK: a heavy call carrying >1000 RUNES of gas clears every fee cap')
        # 20M gas is the single-output standardness ceiling (half the 40M block
        # gas limit, solver.cpp); at 0.00006 RUNES/gas that is 1200 RUNES of gas
        # riding in the fee. Contract transactions are exempt from -maxtxfee and
        # maxfeerate by design, so this must relay.
        balance_before = self.node.getbalance()
        heavy = self.node.sendtocontract(self.contract_address, COUNTER_INC, 0, 20000000, "0.00006000")['txid']
        assert heavy in self.node.getrawmempool()
        self.generate(self.node, 1)
        receipt = self.node.gettransactionreceipt(heavy)[0]
        assert_equal(receipt['excepted'], 'None')
        fee_paid = balance_before - self.node.getbalance()
        assert fee_paid > 1000, "expected >1000 RUNES total cost, got %s" % fee_paid
        assert_equal(self.counter_value(), 6)

        self.log.info('POST-FORK: wallet defaults follow the DGP: createcontract with no explicit price')
        new_contract = self.node.createcontract(COUNTER_BYTECODE)['address']
        self.generate(self.node, 1)
        assert new_contract in self.node.listcontracts()

        self.log.info('POST-FORK: delegation remove + re-delegate still round-trips')
        self.node.removedelegationforaddress(self.delegator_address)
        self.generate(self.node, 1)
        info = self.node.getdelegationinfoforaddress(self.delegator_address)
        assert_equal(info['verified'], False)
        self.node.sendtoaddress(self.delegator_address, 300)
        self.generate(self.node, 1)
        self.set_and_verify_delegation()

        self.log.info('SYNC PROOF: -reindex revalidates the whole chain across the fork')
        tip_hash = self.node.getbestblockhash()
        tip_height = self.node.getblockcount()
        self.restart_node(0, extra_args=self.extra_args[0] + ['-reindex'])
        self.wait_until(lambda: self.node.getblockcount() == tip_height, timeout=900)
        assert_equal(self.node.getbestblockhash(), tip_hash)
        assert_equal(self.node.getdgpinfo()['mingasprice'], NEW_MIN_GAS_PRICE)
        assert_equal(self.counter_value(), 6)
        self.log.info('Reindexed to the same tip: pre-fork 40-gas blocks and post-fork 4000-gas blocks both validate')


if __name__ == '__main__':
    RunebaseGasPriceForkTest(__file__).main()
