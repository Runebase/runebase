// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2014-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#pragma once

#include <string>
#include <libdevcore/FixedHash.h>
#include <libethcore/Common.h>

namespace dev
{
namespace eth
{

/// The network id.
enum class Network
{
    runebaseNetwork = 1
};

std::string const& genesisInfo(Network _n);
h256 const& genesisStateRoot(Network _n);

/// Set the improvements activation blocks for Runebase
struct EVMConsensus
{
    EVMConsensus() {}
    EVMConsensus(int nHeight) :
        QIP6Height(nHeight),
        QIP7Height(nHeight),
        nMuirGlacierHeight(nHeight),
        nLondonHeight(nHeight),
        nShanghaiHeight(nHeight),
        nCancunHeight(nHeight)
    {}

    int QIP6Height = 0x7fffffff;
    int QIP7Height = 0x7fffffff;
    int nMuirGlacierHeight = 0x7fffffff;
    int nLondonHeight = 0x7fffffff;
    int nShanghaiHeight = 0x7fffffff;
    int nCancunHeight = 0x7fffffff;
};

/**
 * @brief genesisInfoRunebase Get the genesis information for EVM
 * @param _n Network type
 * @param _consensus Runebase network consensus parameters (mainnet, testnet, signet or regtest parameters)
 * @return Genesis information for EVM
 */
std::string genesisInfoRunebase(Network _n, EVMConsensus _consensus);

}
}
