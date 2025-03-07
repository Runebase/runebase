#ifndef RUNEBASE_WALLET_RPC_ADDRESSES_H
#define RUNEBASE_WALLET_RPC_ADDRESSES_H

#include <addresstype.h>
#include <univalue.h>

namespace wallet {
class CWallet;

UniValue DescribeWalletAddress(const CWallet& wallet, const CTxDestination& dest);
} //  namespace wallet

#endif // RUNEBASE_WALLET_RPC_ADDRESSES_H
