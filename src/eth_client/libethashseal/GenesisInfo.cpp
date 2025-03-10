
// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2015-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.
#include "GenesisInfo.h"
#include <regex>
using namespace dev;

//Client configurations
#include "genesis/runebaseNetwork.cpp"

std::string const& dev::eth::genesisInfo(Network _n)
{
    switch (_n)
    {
    //Client genesis
    case Network::runebaseNetwork: return c_genesisInfoRunebaseNetwork;

    default:
        throw std::invalid_argument("Invalid network value");
    }
}

h256 const& dev::eth::genesisStateRoot(Network _n)
{
    switch (_n)
    {
    case Network::runebaseNetwork: return c_genesisStateRootRunebaseNetwork;
    default:
        throw std::invalid_argument("Invalid network value");
    }
}

void ReplaceInt(uint64_t number, const std::string& key, std::string& str)
{
    // Convert the number into hex string
    std::string num_hex = dev::toHexPrefixed(dev::toCompactBigEndian(number));

    // Search for key in str and replace it with the hex string
    std::string str_replaced = std::regex_replace(str, std::regex(key), num_hex);
    str = str_replaced;
}

std::string dev::eth::genesisInfoRunebase(Network _n, EVMConsensus _consensus)
{
    std::string _genesisInfo = dev::eth::genesisInfo(_n);
    ReplaceInt(_consensus.QIP6Height,         "QIP6_STARTING_BLOCK", _genesisInfo);
    ReplaceInt(_consensus.QIP7Height,         "QIP7_STARTING_BLOCK", _genesisInfo);
    ReplaceInt(_consensus.nMuirGlacierHeight, "MUIR_STARTING_BLOCK", _genesisInfo);
    ReplaceInt(_consensus.nLondonHeight,      "LONDON_STARTING_BLOCK", _genesisInfo);
    ReplaceInt(_consensus.nShanghaiHeight,    "SHANGHAI_STARTING_BLOCK", _genesisInfo);
    ReplaceInt(_consensus.nCancunHeight,      "CANCUN_STARTING_BLOCK", _genesisInfo);
    return _genesisInfo;
}
