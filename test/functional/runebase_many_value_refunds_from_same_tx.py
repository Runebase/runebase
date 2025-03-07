#!/usr/bin/env python3

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.p2p import *
from test_framework.runebase import *
from test_framework.address import *
import time

class RunebaseManyValueRefundsFromSameTxTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.node = self.nodes[0]
        self.node.generate(10+COINBASE_MATURITY)
        """
        pragma solidity ^0.4.12;

        contract Test {
            function () {}
        }
        """
        contract_bytecode = "60606040523415600e57600080fd5b5b603f80601c6000396000f30060606040525b3415600f57600080fd5b5b5b0000a165627a7a7230582058c936974fe6daaa8267ff5da1c805b0e7442b9cc687162114dfb1cb6d6f62bd0029"
        contract_address = self.node.createcontract(contract_bytecode)['address']
        self.node.generate(1)
        tx = CTransaction()
        tx.vin = [make_vin(self.node, int(2*(COIN + RUNEBASE_MIN_GAS_PRICE*100000)))]
        tx.vout = []
        tx.vout.append(CTxOut(int(COIN), CScript([b"\x04", CScriptNum(100000), CScriptNum(RUNEBASE_MIN_GAS_PRICE), hex_str_to_bytes("00"), hex_str_to_bytes(contract_address), OP_CALL])))
        tx.vout.append(CTxOut(int(COIN), CScript([b"\x04", CScriptNum(100000), CScriptNum(RUNEBASE_MIN_GAS_PRICE), hex_str_to_bytes("00"), hex_str_to_bytes(contract_address), OP_CALL])))

        signed_tx_raw = self.node.signrawtransactionwithwallet(bytes_to_hex_str(tx.serialize()))['hex']
        self.node.sendrawtransaction(signed_tx_raw)
        block_count = self.node.getblockcount()
        self.node.generate(1)
        assert_equal(self.node.getblockcount(), block_count+1)

if __name__ == '__main__':
    RunebaseManyValueRefundsFromSameTxTest().main()
