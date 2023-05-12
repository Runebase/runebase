#include <runebase/runebasetoken.h>
#include <validation.h>
#include <util/moneystr.h>
#include <util/contractabi.h>
#include <key_io.h>
#include <util/strencodings.h>
#include <util/convert.h>
#include <libethcore/ABI.h>

namespace RunebaseToken_NS
{
const char *TOKEN_ABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_spender\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_from\",\"type\":\"address\"},{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"burn\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_from\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"burnFrom\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_spender\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"},{\"name\":\"_extraData\",\"type\":\"bytes\"}],\"name\":\"approveAndCall\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"initialSupply\",\"type\":\"uint256\"},{\"name\":\"tokenName\",\"type\":\"string\"},{\"name\":\"decimalUnits\",\"type\":\"uint8\"},{\"name\":\"tokenSymbol\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Burn\",\"type\":\"event\"}]";
const char *PARAM_ADDRESS = "address";
const char *PARAM_DATAHEX = "datahex";
const char *PARAM_AMOUNT = "amount";
const char *PARAM_GASLIMIT = "gaslimit";
const char *PARAM_GASPRICE = "gasprice";
const char *PARAM_SENDER = "sender";
const char *PARAM_BROADCAST = "broadcast";
const char *PARAM_CHANGE_TO_SENDER = "changeToSender";
const char *PARAM_PSBT = "psbt";
}

bool RunebaseTokenExec::execValid(const int &, const bool &)
{
    return false;
}

bool RunebaseTokenExec::execEventsValid(const int &, const int64_t &)
{
    return false;
}

bool RunebaseTokenExec::exec(const bool &, const std::map<std::string, std::string> &, std::string &, std::string &)
{
    return false;
}

bool RunebaseTokenExec::execEvents(const int64_t &, const int64_t &, const int64_t&, const std::string &, const std::string &, const std::string &, const int &, std::vector<TokenEvent> &)
{
    return false;
}

bool RunebaseTokenExec::privateKeysDisabled()
{
    return false;
}

RunebaseTokenExec::~RunebaseTokenExec()
{}

struct RunebaseTokenData
{
    std::map<std::string, std::string> lstParams;
    std::string address;
    RunebaseTokenExec* tokenExec;
    ContractABI* ABI;
    int funcName;
    int funcApprove;
    int funcTotalSupply;
    int funcTransferFrom;
    int funcDecimals;
    int funcBurn;
    int funcBalanceOf;
    int funcBurnFrom;
    int funcSymbol;
    int funcTransfer;
    int funcApproveAndCall;
    int funcAllowance;
    int evtTransfer;
    int evtBurn;

    std::string txid;
    std::string psbt;
    std::string errorMessage;

    RunebaseTokenData():
        tokenExec(0),
        ABI(0),
        funcName(-1),
        funcApprove(-1),
        funcTotalSupply(-1),
        funcTransferFrom(-1),
        funcDecimals(-1),
        funcBurn(-1),
        funcBalanceOf(-1),
        funcBurnFrom(-1),
        funcSymbol(-1),
        funcTransfer(-1),
        funcApproveAndCall(-1),
        funcAllowance(-1),
        evtTransfer(-1),
        evtBurn(-1)
    {}
};

bool RunebaseToken::ToHash160(const std::string& strRunebaseAddress, std::string& strHash160)
{
    CTxDestination runebaseAddress = DecodeDestination(strRunebaseAddress);
    if(!IsValidDestination(runebaseAddress))
        return false;
    if(std::holds_alternative<PKHash>(runebaseAddress)){
        PKHash keyid = std::get<PKHash>(runebaseAddress);
        strHash160 = HexStr(valtype(keyid.begin(),keyid.end()));
    }else{
        return false;
    }
    return true;
}

bool RunebaseToken::ToRunebaseAddress(const std::string& strHash160, std::string& strRunebaseAddress)
{
    uint160 key(ParseHex(strHash160.c_str()));
    PKHash keyid(key);
    CTxDestination runebaseAddress = keyid;
    if(IsValidDestination(runebaseAddress)){
        strRunebaseAddress = EncodeDestination(runebaseAddress);
        return true;
    }
    return false;
}

uint256 RunebaseToken::ToUint256(const std::string &data)
{
    dev::bytes rawData = dev::fromHex(data);
    dev::bytesConstRef o(&rawData);
    dev::u256 outData = dev::eth::ABIDeserialiser<dev::u256>::deserialise(o);
    return u256Touint(outData);
}

RunebaseToken::RunebaseToken():
    d(0)
{
    d = new RunebaseTokenData();
    clear();

    // Compute functions indexes
    d->ABI = new ContractABI();
    if(d->ABI->loads(RunebaseToken_NS::TOKEN_ABI))
    {
        for(size_t i = 0; i < d->ABI->functions.size(); i++)
        {
            FunctionABI func = d->ABI->functions[i];
            if(func.name == "name")
            {
                d->funcName = i;
            }
            else if(func.name == "approve")
            {
                d->funcApprove = i;
            }
            else if(func.name == "totalSupply")
            {
                d->funcTotalSupply = i;
            }
            else if(func.name == "transferFrom")
            {
                d->funcTransferFrom = i;
            }
            else if(func.name == "decimals")
            {
                d->funcDecimals = i;
            }
            else if(func.name == "burn")
            {
                d->funcBurn = i;
            }
            else if(func.name == "balanceOf")
            {
                d->funcBalanceOf = i;
            }
            else if(func.name == "burnFrom")
            {
                d->funcBurnFrom = i;
            }
            else if(func.name == "symbol")
            {
                d->funcSymbol = i;
            }
            else if(func.name == "transfer")
            {
                d->funcTransfer = i;
            }
            else if(func.name == "approveAndCall")
            {
                d->funcApproveAndCall = i;
            }
            else if(func.name == "allowance")
            {
                d->funcAllowance = i;
            }
            else if(func.name == "Transfer")
            {
                d->evtTransfer = i;
            }
            else if(func.name == "Burn")
            {
                d->evtBurn = i;
            }
        }
    }
}

RunebaseToken::~RunebaseToken()
{
    d->tokenExec = 0;

    if(d)
        delete d;
    d = 0;
}

void RunebaseToken::setAddress(const std::string &address)
{
    d->lstParams[RunebaseToken_NS::PARAM_ADDRESS] = address;
}

void RunebaseToken::setDataHex(const std::string &datahex)
{
    d->lstParams[RunebaseToken_NS::PARAM_DATAHEX] = datahex;
}

void RunebaseToken::setAmount(const std::string &amount)
{
    d->lstParams[RunebaseToken_NS::PARAM_AMOUNT] = amount;
}

void RunebaseToken::setGasLimit(const std::string &gaslimit)
{
    d->lstParams[RunebaseToken_NS::PARAM_GASLIMIT] = gaslimit;
}

void RunebaseToken::setGasPrice(const std::string &gasPrice)
{
    d->lstParams[RunebaseToken_NS::PARAM_GASPRICE] = gasPrice;
}

void RunebaseToken::setSender(const std::string &sender)
{
    d->lstParams[RunebaseToken_NS::PARAM_SENDER] = sender;
}

void RunebaseToken::clear()
{
    d->lstParams.clear();

    setAmount("0");
    setGasPrice(FormatMoney(DEFAULT_GAS_PRICE));
    setGasLimit(std::to_string(DEFAULT_GAS_LIMIT_OP_SEND));

    d->lstParams[RunebaseToken_NS::PARAM_BROADCAST] = "true";
    d->lstParams[RunebaseToken_NS::PARAM_CHANGE_TO_SENDER] = "true";
}

std::string RunebaseToken::getTxId()
{
    return d->txid;
}

std::string RunebaseToken::getPsbt()
{
    return d->psbt;
}

void RunebaseToken::setTxId(const std::string& txid)
{
    d->txid = txid;
}

bool RunebaseToken::name(std::string &result, bool sendTo)
{
    std::vector<std::string> input;
    std::vector<std::string> output;
    if(!exec(input, d->funcName, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            result = output[0];
    }

    return true;
}

bool RunebaseToken::approve(const std::string &_spender, const std::string &_value, bool &success, bool sendTo)
{
    std::string spender = _spender;
    if(!ToHash160(spender, spender))
    {
        return false;
    }

    std::vector<std::string> input;
    input.push_back(spender);
    input.push_back(_value);
    std::vector<std::string> output;

    if(!exec(input, d->funcApprove, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            success = output[0] == "true";
    }

    return true;
}

bool RunebaseToken::totalSupply(std::string &result, bool sendTo)
{
    std::vector<std::string> input;
    std::vector<std::string> output;
    if(!exec(input, d->funcTotalSupply, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            result = output[0];
    }

    return true;
}

bool RunebaseToken::transferFrom(const std::string &_from, const std::string &_to, const std::string &_value, bool &success, bool sendTo)
{
    std::string from = _from;
    if(!ToHash160(from, from))
    {
        return false;
    }
    std::string to = _to;
    if(!ToHash160(to, to))
    {
        return false;
    }

    std::vector<std::string> input;
    input.push_back(from);
    input.push_back(to);
    input.push_back(_value);
    std::vector<std::string> output;

    if(!exec(input, d->funcTransferFrom, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            success = output[0] == "true";
    }

    return true;
}

bool RunebaseToken::decimals(std::string &result, bool sendTo)
{
    std::vector<std::string> input;
    std::vector<std::string> output;
    if(!exec(input, d->funcDecimals, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            result = output[0];
    }

    return true;
}

bool RunebaseToken::decimals(uint32_t &result)
{
    std::string str;
    bool ret = decimals(str);
    if(ret) ret &= ParseUInt32(str, &result);
    if(ret) ret &= result <= 77;
    return ret;
}

bool RunebaseToken::burn(const std::string &_value, bool &success, bool sendTo)
{
    std::vector<std::string> input;
    input.push_back(_value);
    std::vector<std::string> output;

    if(!exec(input, d->funcBurn, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            success = output[0] == "true";
    }

    return true;
}

bool RunebaseToken::balanceOf(std::string &result, bool sendTo)
{
    std::string spender = d->lstParams[RunebaseToken_NS::PARAM_SENDER];
    return balanceOf(spender, result, sendTo);
}

bool RunebaseToken::balanceOf(const std::string &_spender, std::string &result, bool sendTo)
{
    std::string spender = _spender;
    if(!ToHash160(spender, spender))
    {
        return false;
    }

    std::vector<std::string> input;
    input.push_back(spender);
    std::vector<std::string> output;

    if(!exec(input, d->funcBalanceOf, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            result = output[0];
    }

    return true;
}

bool RunebaseToken::burnFrom(const std::string &_from, const std::string &_value, bool &success, bool sendTo)
{
    std::string from = _from;
    if(!ToHash160(from, from))
    {
        return false;
    }

    std::vector<std::string> input;
    input.push_back(from);
    input.push_back(_value);
    std::vector<std::string> output;

    if(!exec(input, d->funcBurnFrom, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            success = output[0] == "true";
    }

    return true;
}

bool RunebaseToken::symbol(std::string &result, bool sendTo)
{
    std::vector<std::string> input;
    std::vector<std::string> output;
    if(!exec(input, d->funcSymbol, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            result = output[0];
    }

    return true;
}

bool RunebaseToken::transfer(const std::string &_to, const std::string &_value, bool& success, bool sendTo)
{
    std::string to = _to;
    if(!ToHash160(to, to))
    {
        return false;
    }

    std::vector<std::string> input;
    input.push_back(to);
    input.push_back(_value);
    std::vector<std::string> output;

    if(!exec(input, d->funcTransfer, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            success = output[0] == "true";
    }

    return true;
}

bool RunebaseToken::approveAndCall(const std::string &_spender, const std::string &_value, const std::string &_extraData, bool &success, bool sendTo)
{
    std::string spender = _spender;
    if(!ToHash160(spender, spender))
    {
        return false;
    }

    std::vector<std::string> input;
    input.push_back(spender);
    input.push_back(_value);
    input.push_back(_extraData);
    std::vector<std::string> output;

    if(!exec(input, d->funcApproveAndCall, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            success = output[0] == "true";
    }

    return true;
}

bool RunebaseToken::allowance(const std::string &_from, const std::string &_to, std::string &result, bool sendTo)
{
    std::string from = _from;
    if(!ToHash160(from, from))
    {
        return false;
    }
    std::string to = _to;
    if(!ToHash160(to, to))
    {
        return false;
    }

    std::vector<std::string> input;
    input.push_back(from);
    input.push_back(to);
    std::vector<std::string> output;

    if(!exec(input, d->funcAllowance, output, sendTo))
        return false;

    if(!sendTo)
    {
        if(output.size() == 0)
            return false;
        else
            result = output[0];
    }

    return true;
}

bool RunebaseToken::transferEvents(std::vector<TokenEvent> &tokenEvents, int64_t fromBlock, int64_t toBlock, int64_t minconf)
{
    return execEvents(fromBlock, toBlock, minconf, d->evtTransfer, tokenEvents);
}

bool RunebaseToken::burnEvents(std::vector<TokenEvent> &tokenEvents, int64_t fromBlock, int64_t toBlock, int64_t minconf)
{
    return execEvents(fromBlock, toBlock, minconf, d->evtBurn, tokenEvents);
}

bool RunebaseToken::exec(const std::vector<std::string> &input, int func, std::vector<std::string> &output, bool sendTo)
{
    // Convert the input data into hex encoded binary data
    d->txid = "";
    d->psbt = "";
    if(d->tokenExec == 0 || !(d->tokenExec->execValid(func, sendTo)))
        return false;
    std::string strData;
    FunctionABI function = d->ABI->functions[func];
    std::vector<std::vector<std::string>> values;
    for(size_t i = 0; i < input.size(); i++)
    {
        std::vector<std::string> param;
        param.push_back(input[i]);
        values.push_back(param);
    }
    std::vector<ParameterABI::ErrorType> errors;
    if(!function.abiIn(values, strData, errors))
        return false;
    setDataHex(strData);

    // Execute the command and get the result
    std::string result;
    d->errorMessage.clear();    
    if(!(d->tokenExec->exec(sendTo, d->lstParams, result, d->errorMessage)))
        return false;

    // Get the result from calling function
    if(!sendTo)
    {
        std::string rawData = result;
        std::vector<std::vector<std::string>> values;
        std::vector<ParameterABI::ErrorType> errors;
        if(!function.abiOut(rawData, values, errors))
            return false;
        for(size_t i = 0; i < values.size(); i++)
        {
            std::vector<std::string> param = values[i];
            output.push_back(param.size() ? param[0] : "");
        }
    }
    else
    {
        if(d->tokenExec->privateKeysDisabled())
        {
            d->psbt = result;
        }
        else
        {
            d->txid = result;
        }
    }

    return true;
}

void RunebaseToken::addTokenEvent(std::vector<TokenEvent> &tokenEvents, TokenEvent tokenEvent)
{
    // Check if the event is from an existing token transaction and update the value
    bool found = false;
    for(size_t i = 0; i < tokenEvents.size(); i++)
    {
        // Compare the event data
        TokenEvent tokenTx = tokenEvents[i];
        if(tokenTx.address != tokenEvent.address) continue;
        if(tokenTx.sender != tokenEvent.sender) continue;
        if(tokenTx.receiver != tokenEvent.receiver) continue;
        if(tokenTx.blockHash != tokenEvent.blockHash) continue;
        if(tokenTx.blockNumber != tokenEvent.blockNumber) continue;
        if(tokenTx.transactionHash != tokenEvent.transactionHash) continue;

        // Update the value
        dev::u256 tokenValue = uintTou256(tokenTx.value) + uintTou256(tokenEvent.value);
        tokenTx.value = u256Touint(tokenValue);
        tokenEvents[i] = tokenTx;
        found = true;
        break;
    }

    // Add new event
    if(!found)
        tokenEvents.push_back(tokenEvent);
}

bool RunebaseToken::execEvents(int64_t fromBlock, int64_t toBlock, int64_t minconf, int func, std::vector<TokenEvent> &tokenEvents)
{
    // Check parameters
    if(d->tokenExec == 0 || !(d->tokenExec->execEventsValid(func, fromBlock)))
        return false;

    //  Get function
    FunctionABI function = d->ABI->functions[func];

    // Search for events
    std::vector<TokenEvent> result;
    std::string eventName = function.selector();
    std::string contractAddress = d->lstParams[RunebaseToken_NS::PARAM_ADDRESS];
    std::string senderAddress = d->lstParams[RunebaseToken_NS::PARAM_SENDER];
    ToHash160(senderAddress, senderAddress);
    senderAddress  = "000000000000000000000000" + senderAddress;
    int numTopics = function.numIndexed() + 1;
    if(!(d->tokenExec->execEvents(fromBlock, toBlock, minconf, eventName, contractAddress, senderAddress, numTopics, result)))
        return false;

    // Parse the result events
    for(const TokenEvent& tokenEvent : result)
    {
        addTokenEvent(tokenEvents, tokenEvent);
    }

    return true;
}

std::string RunebaseToken::getErrorMessage()
{
    return d->errorMessage;
}

void RunebaseToken::setRunebaseTokenExec(RunebaseTokenExec *tokenExec)
{
    d->tokenExec = tokenExec;
}

const char* RunebaseToken::paramAddress()
{
    return RunebaseToken_NS::PARAM_ADDRESS;
}

const char* RunebaseToken::paramDatahex()
{
    return RunebaseToken_NS::PARAM_DATAHEX;
}

const char* RunebaseToken::paramAmount()
{
    return RunebaseToken_NS::PARAM_AMOUNT;
}

const char* RunebaseToken::paramGasLimit()
{
    return RunebaseToken_NS::PARAM_GASLIMIT;
}

const char* RunebaseToken::paramGasPrice()
{
    return RunebaseToken_NS::PARAM_GASPRICE;
}

const char* RunebaseToken::paramSender()
{
    return RunebaseToken_NS::PARAM_SENDER;
}

const char* RunebaseToken::paramBroadcast()
{
    return RunebaseToken_NS::PARAM_BROADCAST;
}

const char* RunebaseToken::paramChangeToSender()
{
    return RunebaseToken_NS::PARAM_CHANGE_TO_SENDER;
}

const char* RunebaseToken::paramPsbt()
{
    return RunebaseToken_NS::PARAM_PSBT;
}
