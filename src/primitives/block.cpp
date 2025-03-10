// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <crypto/common.h>
#include <pubkey.h>
#include <streams.h>

// Used to serialize the header without signature
// Workaround due to removing serialization templates in Bitcoin Core 0.18
class CBlockHeaderSign
{
public:
    CBlockHeaderSign(const CBlockHeader& header)
    {
        fHasProofOfDelegation = header.HasProofOfDelegation();
        nVersion = header.nVersion;
        hashPrevBlock = header.hashPrevBlock;
        hashMerkleRoot = header.hashMerkleRoot;
        nTime = header.nTime;
        nBits = header.nBits;
        nNonce = header.nNonce;
        hashStateRoot = header.hashStateRoot;
        hashUTXORoot = header.hashUTXORoot;
        prevoutStake = header.prevoutStake;
        vchBlockDlgt = header.GetProofOfDelegation();
    }

    SERIALIZE_METHODS(CBlockHeaderSign, obj) { 
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.hashStateRoot, obj.hashUTXORoot, obj.prevoutStake);
        if(obj.fHasProofOfDelegation)
        {
            READWRITE(obj.vchBlockDlgt);
        }
    }

private:
    bool fHasProofOfDelegation;

    // header without signature
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 hashStateRoot;
    uint256 hashUTXORoot;
    COutPoint prevoutStake;
    std::vector<unsigned char> vchBlockDlgt;
};

uint256 CBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetHash();
}

uint256 CBlockHeader::GetHashWithoutSign() const
{
    return (HashWriter{} << CBlockHeaderSign(*this)).GetHash();
}

std::string CBlockHeader::GetWithoutSign() const
{
    DataStream ss;
    ss << CBlockHeaderSign(*this);
    return EncodeBase64(ss.str());
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, hashStateRoot=%s, hashUTXORoot=%s, blockSig=%s, proof=%s, prevoutStake=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        hashStateRoot.ToString(), // runebase
        hashUTXORoot.ToString(), // runebase
        HexStr(vchBlockSigDlgt),
        IsProofOfStake() ? "PoS" : "PoW",
        prevoutStake.ToString(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

std::vector<unsigned char> CBlockHeader::GetBlockSignature() const
{
    if(vchBlockSigDlgt.size() < 2 * CPubKey::COMPACT_SIGNATURE_SIZE)
    {
        return vchBlockSigDlgt;
    }

    return std::vector<unsigned char>(vchBlockSigDlgt.begin(), vchBlockSigDlgt.end() - CPubKey::COMPACT_SIGNATURE_SIZE );
}

std::vector<unsigned char> CBlockHeader::GetProofOfDelegation() const
{
    if(vchBlockSigDlgt.size() < 2 * CPubKey::COMPACT_SIGNATURE_SIZE)
    {
        return std::vector<unsigned char>();
    }

    return std::vector<unsigned char>(vchBlockSigDlgt.begin() + vchBlockSigDlgt.size() - CPubKey::COMPACT_SIGNATURE_SIZE, vchBlockSigDlgt.end());

}

bool CBlockHeader::HasProofOfDelegation() const
{
    return vchBlockSigDlgt.size() >= 2 * CPubKey::COMPACT_SIGNATURE_SIZE;
}

void CBlockHeader::SetBlockSignature(const std::vector<unsigned char> &vchSign)
{
    if(HasProofOfDelegation())
    {
        std::vector<unsigned char> vchPoD = GetProofOfDelegation();
        vchBlockSigDlgt = vchSign;
        vchBlockSigDlgt.insert(vchBlockSigDlgt.end(), vchPoD.begin(), vchPoD.end());
    }
    else
    {
        vchBlockSigDlgt = vchSign;
    }
}

void CBlockHeader::SetProofOfDelegation(const std::vector<unsigned char> &vchPoD)
{
    std::vector<unsigned char> vchSign = GetBlockSignature();
    if(vchSign.size() != CPubKey::COMPACT_SIGNATURE_SIZE)
    {
        vchSign.resize(CPubKey::COMPACT_SIGNATURE_SIZE, 0);
    }
    vchBlockSigDlgt = vchSign;
    vchBlockSigDlgt.insert(vchBlockSigDlgt.end(), vchPoD.begin(), vchPoD.end());
}
