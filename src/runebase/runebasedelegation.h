#ifndef RUNEBASEDELEGATION_H
#define RUNEBASEDELEGATION_H
#include <string>
#include <vector>
#include <map>
#include <stdint.h>
#include <uint256.h>
#include <runebase/posutils.h>

class RunebaseDelegationPriv;
class ContractABI;
class ChainstateManager;
class Chainstate;

extern const std::string strDelegationsABI;
const ContractABI &DelegationABI();

struct DelegationItem : public Delegation
{
    DelegationItem()
    {}

    bool IsNull() const
    {
        return Delegation::IsNull() &&
                delegate == uint160();
    }

    uint160 delegate;
};

enum DelegationType
{
    DELEGATION_NONE = 0,
    DELEGATION_ADD = 1,
    DELEGATION_REMOVE = 2,
};

struct DelegationEvent
{
    DelegationItem item;
    DelegationType type;

    DelegationEvent():
        type(DelegationType::DELEGATION_NONE)
    {}
};

/**
 * @brief The IRunebaseStaker class Delegation filter
 */
class IDelegationFilter
{
public:
    virtual bool Match(const DelegationEvent& event) const = 0;
};

/**
 * @brief The RunebaseDelegation class Communicate with the runebase delegation contract
 */
class RunebaseDelegation {
    
public:
    /**
     * @brief RunebaseDelegation Constructor
     */
    RunebaseDelegation();

    /**
     * @brief ~RunebaseDelegation Destructor
     */
    virtual ~RunebaseDelegation();

    /**
     * @brief GetDelegation Get delegation for an address
     * @param address Public key hash address
     * @param delegation Delegation information for an address
     * @return true/false
     */
    bool GetDelegation(const uint160& address, Delegation& delegation, Chainstate& chainstate) const;

    /**
     * @brief VerifyDelegation Verify delegation for an address
     * @param address Public key hash address
     * @param delegation Delegation information for an address
     * @return true/false
     */
    static bool VerifyDelegation(const uint160& address, const Delegation& delegation);

    /**
     * @brief FilterDelegationEvents Filter delegation events
     * @param events Output list of delegation events for the filter
     * @param filter Delegation filter
     * @param chainman Chain state manager
     * @param fromBlock Start with block
     * @param toBlock End with block, -1 mean all available
     * @param minconf Minimum confirmations
     * @return true/false
     */
    bool FilterDelegationEvents(std::vector<DelegationEvent>& events, const IDelegationFilter& filter, ChainstateManager &chainman, int fromBlock = 0, int toBlock = -1, int minconf = 0) const;

    /**
     * @brief DelegationsFromEvents Get the delegations from the events
     * @param events Delegation event list
     * @return List of delegations
     */
    static std::map<uint160, Delegation> DelegationsFromEvents(const std::vector<DelegationEvent>& events);

    /**
     * @brief UpdateDelegationsFromEvents Update the delegations from the events
     * @param events Delegation event list
     * @param delegations List of delegations to be updated
     */
    static void UpdateDelegationsFromEvents(const std::vector<DelegationEvent>& events, std::map<uint160, Delegation>& delegations);

    /**
     * @brief ExistDelegationContract Delegation contract exist check
     * @return true/false
     */
    bool ExistDelegationContract() const;

    /**
     * @brief BytecodeRemove Bytecode for remove delegation
     * @return Bytecode
     */
    static std::string BytecodeRemove();

    /**
     * @brief BytecodeAdd Bytecode for add delegation
     * @param hexStaker Staker hex address
     * @param fee Staker fee
     * @param PoD Proof of delegation
     * @param datahex Bytecode
     * @param errorMessage Error message
     * @return true/false
     */
    static bool BytecodeAdd(const std::string& hexStaker, const int& fee, const std::vector<unsigned char>& PoD, std::string& datahex, std::string& errorMessage);

    /**
     * @brief IsAddBytecode Quick check for if the bytecode is for addDelegation method
     * @param data Bytecode of contract
     * @return true/false
     */
    static bool IsAddBytecode(const std::vector<unsigned char>& data);

    /**
     * @brief GetUnsignedStaker Get unsigned staker address from PoD
     * @param data Bytecode of contract
     * @param hexStaker Staker hex address
     * @return true/false
     */
    static bool GetUnsignedStaker(const std::vector<unsigned char>& data, std::string& hexStaker);

    /**
     * @brief SetSignedStaker Set signed staker address into PoD
     * @param data Bytecode of contract
     * @param base64PoD Staker address signed in base64
     * @return true/false
     */
    static bool SetSignedStaker(std::vector<unsigned char>& data, const std::string& base64PoD);

private:
    RunebaseDelegation(const RunebaseDelegation&);
    RunebaseDelegation& operator=(const RunebaseDelegation&);
    RunebaseDelegationPriv* priv;
};
#endif
