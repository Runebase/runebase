#ifndef RUNEBASE_WALLET_RPC_CONTRACT_H
#define RUNEBASE_WALLET_RPC_CONTRACT_H

#include <span.h>

class CRPCCommand;

namespace wallet {
Span<const CRPCCommand> GetContractRPCCommands();
} // namespace wallet

#endif // RUNEBASE_WALLET_RPC_CONTRACT_H
