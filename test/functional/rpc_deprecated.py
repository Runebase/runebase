#!/usr/bin/env python3
# Copyright (c) 2017-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test deprecation of RPC calls."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.runebase import convert_btc_address_to_runebase
class DeprecatedRpcTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], ["-deprecatedrpc=generate"]]

    def skip_test_if_missing_module(self):
        # The generate RPC method requires the wallet to be compiled
        self.skip_if_no_wallet()

    def run_test(self):
        # This test should be used to verify correct behaviour of deprecated
        # RPC methods with and without the -deprecatedrpc flags. For example:
        #
        # self.log.info("Make sure that -deprecatedrpc=createmultisig allows it to take addresses")
        # assert_raises_rpc_error(-5, "Invalid public key", self.nodes[0].createmultisig, 1, [self.nodes[0].getnewaddress()])
        # self.nodes[1].createmultisig(1, [self.nodes[1].getnewaddress()])

        self.log.info("Test generate RPC")
        assert_raises_rpc_error(-32, 'The wallet generate rpc method is deprecated', self.nodes[0].rpc.generate, 1)
        self.nodes[1].generate(1)

if __name__ == '__main__':
    DeprecatedRpcTest().main()
