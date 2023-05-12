#ifndef RUNEBASE_WALLET_RPC_MINING_H
#define RUNEBASE_WALLET_RPC_MINING_H

#include <span.h>

class CRPCCommand;

namespace wallet {
Span<const CRPCCommand> GetMiningRPCCommands();
} // namespace wallet

#endif // RUNEBASE_WALLET_RPC_MINING_H
