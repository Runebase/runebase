#ifndef RUNEBASETESTS_TEST_UTILS_H
#define RUNEBASETESTS_TEST_UTILS_H

#include <common/system.h>
#include <validation.h>
#include <util/strencodings.h>
#include <util/convert.h>
#include <test/util/setup_common.h>
#include <boost/filesystem/operations.hpp>
#include <util/fs.h>

#include <random.h>

extern std::unique_ptr<RunebaseState> globalState;

inline void initState(){
    boost::filesystem::path pathTemp;		
    pathTemp = fs::temp_directory_path() / strprintf("test_bitcoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
    boost::filesystem::create_directories(pathTemp);
    const std::string dirRunebase = pathTemp.string();
    const dev::h256 hashDB(dev::sha3(dev::rlp("")));
    globalState = std::unique_ptr<RunebaseState>(new RunebaseState(dev::u256(0), RunebaseState::openDB(dirRunebase, hashDB, dev::WithExisting::Trust), dirRunebase + "/runebaseDB", dev::eth::BaseState::Empty));

    globalState->setRootUTXO(dev::sha3(dev::rlp(""))); // temp
}

inline CBlock generateBlock(){
    CBlock block;
    CMutableTransaction tx;
    std::vector<unsigned char> address(ParseHex("abababababababababababababababababababab"));
    tx.vout.push_back(CTxOut(0, CScript() << OP_DUP << OP_HASH160 << address << OP_EQUALVERIFY << OP_CHECKSIG));
    block.vtx.push_back(MakeTransactionRef(CTransaction(tx)));
    return block;
}

inline dev::Address createRunebaseAddress(dev::h256 hashTx, uint32_t voutNumber){
    uint256 hashTXid(h256Touint(hashTx));
    std::vector<unsigned char> txIdAndVout(hashTXid.begin(), hashTXid.end());
    std::vector<unsigned char> voutNumberChrs;
    if (voutNumberChrs.size() < sizeof(voutNumber))voutNumberChrs.resize(sizeof(voutNumber));
    std::memcpy(voutNumberChrs.data(), &voutNumber, sizeof(voutNumber));
    txIdAndVout.insert(txIdAndVout.end(),voutNumberChrs.begin(),voutNumberChrs.end());

    std::vector<unsigned char> SHA256TxVout(32);
    CSHA256().Write(txIdAndVout.data(), txIdAndVout.size()).Finalize(SHA256TxVout.data());

    std::vector<unsigned char> hashTxIdAndVout(20);
    CRIPEMD160().Write(SHA256TxVout.data(), SHA256TxVout.size()).Finalize(hashTxIdAndVout.data());

    return dev::Address(hashTxIdAndVout);
}


inline RunebaseTransaction createRunebaseTransaction(valtype data, dev::u256 value, dev::u256 gasLimit, dev::u256 gasPrice, dev::h256 hashTransaction, dev::Address recipient, int32_t nvout = 0){
    RunebaseTransaction txEth;
    if(recipient == dev::Address()){
        txEth = RunebaseTransaction(value, gasPrice, gasLimit, data, dev::u256(0));
    } else {
        txEth = RunebaseTransaction(value, gasPrice, gasLimit, recipient, data, dev::u256(0));
    }
    txEth.forceSender(dev::Address("0101010101010101010101010101010101010101"));
    txEth.setHashWith(hashTransaction);
    txEth.setNVout(nvout);
    txEth.setVersion(VersionVM::GetEVMDefault());
    return txEth;
}

inline std::pair<std::vector<ResultExecute>, ByteCodeExecResult> executeBC(std::vector<RunebaseTransaction> txs, ChainstateManager& chainman){
    CBlock block(generateBlock());
    RunebaseDGP runebaseDGP(globalState.get(), chainman.ActiveChainstate(), fGettingValuesDGP);
    uint64_t blockGasLimit = runebaseDGP.getBlockGasLimit(chainman.ActiveChain().Tip()->nHeight + 1);
    ByteCodeExec exec(block, txs, blockGasLimit, chainman.ActiveChain().Tip(), chainman.ActiveChain());
    exec.performByteCode();
    std::vector<ResultExecute> res = exec.getResult();
    ByteCodeExecResult bceExecRes;
    exec.processingResults(bceExecRes); //error handling?
    globalState->db().commit();
    globalState->dbUtxo().commit();
    return std::make_pair(res, bceExecRes);
}

#endif // RUNEBASETESTS_TEST_UTILS_H
