#ifndef RUNEBASE_WALLET_RPC_MINING_H
#define RUNEBASE_WALLET_RPC_MINING_H

#include <span.h>

class CRPCCommand;

namespace wallet {
std::span<const CRPCCommand> GetMiningRPCCommands();
} // namespace wallet

#endif // RUNEBASE_WALLET_RPC_MINING_H
