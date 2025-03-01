// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <kernel/coinstats.h>
#include <kernel/mempool_persist.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <checkqueue.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <flatfile.h>
#include <fs.h>
#include <hash.h>
#include <logging.h>
#include <logging/timer.h>
#include <node/blockstorage.h>
#include <node/interface_ui.h>
#include <node/utxo_snapshot.h>
#include <node/transaction.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <policy/settings.h>
#include <pow.h>
#include <pos.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <shutdown.h>
#include <signet.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h> // For NDEBUG compile time check
#include <util/hasher.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <libethcore/ABI.h>
#include <univalue.h>
#include <util/signstr.h>
#include <runebase/runebaseutils.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <deque>
#include <numeric>
#include <optional>
#include <string>

using kernel::CCoinsStats;
using kernel::CoinStatsHashType;
using kernel::ComputeUTXOStats;
using kernel::LoadMempool;

using fsbridge::FopenFn;
using node::BlockManager;
using node::BlockMap;
using node::CBlockIndexHeightOnlyComparator;
using node::CBlockIndexWorkComparator;
using node::fImporting;
using node::fPruneMode;
using node::fReindex;
using node::ReadBlockFromDisk;
using node::SnapshotMetadata;
using node::UndoReadFromDisk;
using node::UnlinkPrunedFiles;

#define MICRO 0.000001
#define MILLI 0.001

/** Maximum kilobytes for transactions to store for processing during reorg */
static const unsigned int MAX_DISCONNECTED_TX_POOL_SIZE = 20000;
/** Time to wait between writing blocks/block index to disk. */
static constexpr std::chrono::hours DATABASE_WRITE_INTERVAL{1};
/** Time to wait between flushing chainstate to disk. */
static constexpr std::chrono::hours DATABASE_FLUSH_INTERVAL{24};
/** Maximum age of our tip for us to be considered current for fee estimation */
static constexpr std::chrono::hours MAX_FEE_ESTIMATION_TIP_AGE{3};
const std::vector<std::string> CHECKLEVEL_DOC {
    "level 0 reads the blocks from disk",
    "level 1 verifies block validity",
    "level 2 verifies undo data",
    "level 3 checks disconnection of tip blocks",
    "level 4 tries to reconnect the blocks",
    "each level includes the checks of the previous levels",
};
/** The number of blocks to keep below the deepest prune lock.
 *  There is nothing special about this number. It is higher than what we
 *  expect to see in regular mainnet reorgs, but not so high that it would
 *  noticeably interfere with the pruning mechanism.
 * */
static constexpr int PRUNE_LOCK_BUFFER{10};

std::unique_ptr<RunebaseState> globalState;
std::shared_ptr<dev::eth::SealEngineFace> globalSealEngine;
bool fRecordLogOpcodes = false;
bool fIsVMlogFile = false;
bool fGettingValuesDGP = false;
std::set<std::pair<COutPoint, unsigned int>> setStakeSeen;

/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
RecursiveMutex cs_main;

GlobalMutex g_best_block_mutex;
std::condition_variable g_best_block_cv;
uint256 g_best_block;
bool g_parallel_script_checks{false};
bool fAddressIndex = false; // runebase
bool fLogEvents = false;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;

uint256 hashAssumeValid;
arith_uint256 nMinimumChainWork;

const CBlockIndex* Chainstate::FindForkInGlobalIndex(const CBlockLocator& locator) const
{
    AssertLockHeld(cs_main);

    // Find the latest block common to locator and chain - we expect that
    // locator.vHave is sorted descending by height.
    for (const uint256& hash : locator.vHave) {
        const CBlockIndex* pindex{m_blockman.LookupBlockIndex(hash)};
        if (pindex) {
            if (m_chain.Contains(pindex)) {
                return pindex;
            }
            if (pindex->GetAncestor(m_chain.Height()) == m_chain.Tip()) {
                return m_chain.Tip();
            }
        }
    }
    return m_chain.Genesis();
}

std::unique_ptr<StorageResults> pstorageresult;

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       std::vector<CScriptCheck>* pvChecks = nullptr)
                       EXCLUSIVE_LOCKS_REQUIRED(cs_main);

int64_t FutureDrift(uint32_t nTime, int nHeight, const Consensus::Params& consensusParams)
{
    return nTime + consensusParams.StakeTimestampMask(nHeight);
}

bool CheckFinalTxAtTip(const CBlockIndex& active_chain_tip, const CTransaction& tx)
{
    AssertLockHeld(cs_main);

    // CheckFinalTxAtTip() uses active_chain_tip.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than active_chain_tip.Height().
    const int nBlockHeight = active_chain_tip.nHeight + 1;

    // BIP113 requires that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx().
    const int64_t nBlockTime{active_chain_tip.GetMedianTimePast()};

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

bool CheckSequenceLocksAtTip(CBlockIndex* tip,
                        const CCoinsView& coins_view,
                        const CTransaction& tx,
                        LockPoints* lp,
                        bool useExistingLockPoints)
{
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocksAtTip() uses active_chainstate.m_chain.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than active_chainstate.m_chain.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!coins_view.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocksAtTip to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (const int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            // tip->GetAncestor(maxInputHeight) should never return a nullptr
            // because maxInputHeight is always less than the tip height.
            // It would, however, be a bad bug to continue execution, since a
            // LockPoints object with the maxInputBlock member set to nullptr
            // signifies no relative lock time.
            lp->maxInputBlock = Assert(tip->GetAncestor(maxInputHeight));
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

// Returns the script flags which should be checked for a given block
static unsigned int GetBlockScriptFlags(const CBlockIndex& block_index, const ChainstateManager& chainman);

static void LimitMempoolSize(CTxMemPool& pool, CCoinsViewCache& coins_cache)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main, pool.cs)
{
    AssertLockHeld(::cs_main);
    AssertLockHeld(pool.cs);
    int expired = pool.Expire(GetTime<std::chrono::seconds>() - pool.m_expiry);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(pool.m_max_size_bytes, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        coins_cache.Uncache(removed);
}

static bool IsCurrentForFeeEstimation(Chainstate& active_chainstate) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    if (active_chainstate.IsInitialBlockDownload())
        return false;
    if (active_chainstate.m_chain.Tip()->GetBlockTime() < count_seconds(GetTime<std::chrono::seconds>() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (active_chainstate.m_chain.Height() < active_chainstate.m_chainman.m_best_header->nHeight - 1) {
        return false;
    }
    return true;
}

void Chainstate::MaybeUpdateMempoolForReorg(
    DisconnectedBlockTransactions& disconnectpool,
    bool fAddToMempool)
{
    if (!m_mempool) return;

    AssertLockHeld(cs_main);
    AssertLockHeld(m_mempool->cs);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        if (!fAddToMempool || (*it)->IsCoinBase() || (*it)->IsCoinStake() ||
            AcceptToMemoryPool(*this, *it, GetTime(),
                /*bypass_limits=*/true, /*test_accept=*/false).m_result_type !=
                    MempoolAcceptResult::ResultType::VALID) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            m_mempool->removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (m_mempool->exists(GenTxid::Txid((*it)->GetHash()))) {
            vHashUpdate.push_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    m_mempool->UpdateTransactionsFromBlock(vHashUpdate);

    // Predicate to use for filtering transactions in removeForReorg.
    // Checks whether the transaction is still final and, if it spends a coinbase output, mature.
    // Also updates valid entries' cached LockPoints if needed.
    // If false, the tx is still valid and its lockpoints are updated.
    // If true, the tx would be invalid in the next block; remove this entry and all of its descendants.
    const auto filter_final_and_mature = [this](CTxMemPool::txiter it)
        EXCLUSIVE_LOCKS_REQUIRED(m_mempool->cs, ::cs_main) {
        AssertLockHeld(m_mempool->cs);
        AssertLockHeld(::cs_main);
        const CTransaction& tx = it->GetTx();

        // The transaction must be final.
        if (!CheckFinalTxAtTip(*Assert(m_chain.Tip()), tx)) return true;
        LockPoints lp = it->GetLockPoints();
        const bool validLP{TestLockPointValidity(m_chain, lp)};
        CCoinsViewMemPool view_mempool(&CoinsTip(), *m_mempool);
        // CheckSequenceLocksAtTip checks if the transaction will be final in the next block to be
        // created on top of the new chain. We use useExistingLockPoints=false so that, instead of
        // using the information in lp (which might now refer to a block that no longer exists in
        // the chain), it will update lp to contain LockPoints relevant to the new chain.
        if (!CheckSequenceLocksAtTip(m_chain.Tip(), view_mempool, tx, &lp, validLP)) {
            // If CheckSequenceLocksAtTip fails, remove the tx and don't depend on the LockPoints.
            return true;
        } else if (!validLP) {
            // If CheckSequenceLocksAtTip succeeded, it also updated the LockPoints.
            // Now update the mempool entry lockpoints as well.
            m_mempool->mapTx.modify(it, [&lp](CTxMemPoolEntry& e) { e.UpdateLockPoints(lp); });
        }

        // If the transaction spends any coinbase outputs, it must be mature.
        if (it->GetSpendsCoinbase()) {
            for (const CTxIn& txin : tx.vin) {
                auto it2 = m_mempool->mapTx.find(txin.prevout.hash);
                if (it2 != m_mempool->mapTx.end())
                    continue;
                const Coin& coin{CoinsTip().AccessCoin(txin.prevout)};
                assert(!coin.IsSpent());
                const auto mempool_spend_height{m_chain.Tip()->nHeight + 1};
                if ((coin.IsCoinBase() || coin.IsCoinStake()) && mempool_spend_height - coin.nHeight < Params().GetConsensus().CoinbaseMaturity(mempool_spend_height)) {
                    return true;
                }
            }
        }
        // Transaction is still valid and cached LockPoints are updated.
        return false;
    };

    // We also need to remove any now-immature transactions
    m_mempool->removeForReorg(m_chain, filter_final_and_mature);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(*m_mempool, this->CoinsTip());
}

/**
* Checks to avoid mempool polluting consensus critical paths since cached
* signature and script validity results will be reused if we validate this
* transaction again during block validation.
* */
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, TxValidationState& state,
                const CCoinsViewCache& view, const CTxMemPool& pool,
                unsigned int flags, PrecomputedTransactionData& txdata, CCoinsViewCache& coins_tip)
                EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);

        // This coin was checked in PreChecks and MemPoolAccept
        // has been holding cs_main since then.
        Assume(!coin.IsSpent());
        if (coin.IsSpent()) return false;

        // If the Coin is available, there are 2 possibilities:
        // it is available in our current ChainstateActive UTXO set,
        // or it's a UTXO provided by a transaction in our mempool.
        // Ensure the scriptPubKeys in Coins from CoinsView are correct.
        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->GetHash() == txin.prevout.hash);
            assert(txFrom->vout.size() > txin.prevout.n);
            assert(txFrom->vout[txin.prevout.n] == coin.out);
        } else {
            const Coin& coinFromUTXOSet = coins_tip.AccessCoin(txin.prevout);
            assert(!coinFromUTXOSet.IsSpent());
            assert(coinFromUTXOSet.out == coin.out);
        }
    }

    // Call CheckInputScripts() to cache signature and script validity against current tip consensus rules.
    return CheckInputScripts(tx, state, view, flags, /* cacheSigStore= */ true, /* cacheFullScriptStore= */ true, txdata);
}

namespace {

class MemPoolAccept
{
public:
    explicit MemPoolAccept(CTxMemPool& mempool, Chainstate& active_chainstate) : m_pool(mempool), m_view(&m_dummy), m_viewmempool(&active_chainstate.CoinsTip(), m_pool), m_active_chainstate(active_chainstate),
        m_limit_ancestors(m_pool.m_limits.ancestor_count),
        m_limit_ancestor_size(m_pool.m_limits.ancestor_size_vbytes),
        m_limit_descendants(m_pool.m_limits.descendant_count),
        m_limit_descendant_size(m_pool.m_limits.descendant_size_vbytes) {
    }

    // We put the arguments we're handed into a struct, so we can pass them
    // around easier.
    struct ATMPArgs {
        const CChainParams& m_chainparams;
        const int64_t m_accept_time;
        const bool m_bypass_limits;
        /*
         * Return any outpoints which were not previously present in the coins
         * cache, but were added as a result of validating the tx for mempool
         * acceptance. This allows the caller to optionally remove the cache
         * additions if the associated transaction ends up being rejected by
         * the mempool.
         */
        std::vector<COutPoint>& m_coins_to_uncache;
        const bool m_test_accept;
        /** Whether we allow transactions to replace mempool transactions by BIP125 rules. If false,
         * any transaction spending the same inputs as a transaction in the mempool is considered
         * a conflict. */
        const bool m_allow_replacement;
        /** When true, the mempool will not be trimmed when individual transactions are submitted in
         * Finalize(). Instead, limits should be enforced at the end to ensure the package is not
         * partially submitted.
         */
        const bool m_package_submission;
        /** When true, use package feerates instead of individual transaction feerates for fee-based
         * policies such as mempool min fee and min relay fee.
         */
        const bool m_package_feerates;

        /** Parameters for single transaction mempool validation. */
        static ATMPArgs SingleAccept(const CChainParams& chainparams, int64_t accept_time,
                                     bool bypass_limits, std::vector<COutPoint>& coins_to_uncache,
                                     bool test_accept) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ bypass_limits,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ test_accept,
                            /* m_allow_replacement */ true,
                            /* m_package_submission */ false,
                            /* m_package_feerates */ false,
            };
        }

        /** Parameters for test package mempool validation through testmempoolaccept. */
        static ATMPArgs PackageTestAccept(const CChainParams& chainparams, int64_t accept_time,
                                          std::vector<COutPoint>& coins_to_uncache) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ false,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ true,
                            /* m_allow_replacement */ false,
                            /* m_package_submission */ false, // not submitting to mempool
                            /* m_package_feerates */ false,
            };
        }

        /** Parameters for child-with-unconfirmed-parents package validation. */
        static ATMPArgs PackageChildWithParents(const CChainParams& chainparams, int64_t accept_time,
                                                std::vector<COutPoint>& coins_to_uncache) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ false,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ false,
                            /* m_allow_replacement */ false,
                            /* m_package_submission */ true,
                            /* m_package_feerates */ true,
            };
        }

        /** Parameters for a single transaction within a package. */
        static ATMPArgs SingleInPackageAccept(const ATMPArgs& package_args) {
            return ATMPArgs{/* m_chainparams */ package_args.m_chainparams,
                            /* m_accept_time */ package_args.m_accept_time,
                            /* m_bypass_limits */ false,
                            /* m_coins_to_uncache */ package_args.m_coins_to_uncache,
                            /* m_test_accept */ package_args.m_test_accept,
                            /* m_allow_replacement */ true,
                            /* m_package_submission */ false,
                            /* m_package_feerates */ false, // only 1 transaction
            };
        }

    private:
        // Private ctor to avoid exposing details to clients and allowing the possibility of
        // mixing up the order of the arguments. Use static functions above instead.
        ATMPArgs(const CChainParams& chainparams,
                 int64_t accept_time,
                 bool bypass_limits,
                 std::vector<COutPoint>& coins_to_uncache,
                 bool test_accept,
                 bool allow_replacement,
                 bool package_submission,
                 bool package_feerates)
            : m_chainparams{chainparams},
              m_accept_time{accept_time},
              m_bypass_limits{bypass_limits},
              m_coins_to_uncache{coins_to_uncache},
              m_test_accept{test_accept},
              m_allow_replacement{allow_replacement},
              m_package_submission{package_submission},
              m_package_feerates{package_feerates}
        {
        }
    };

    // Single transaction acceptance
    MempoolAcceptResult AcceptSingleTransaction(const CTransactionRef& ptx, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
    * Multiple transaction acceptance. Transactions may or may not be interdependent, but must not
    * conflict with each other, and the transactions cannot already be in the mempool. Parents must
    * come before children if any dependencies exist.
    */
    PackageMempoolAcceptResult AcceptMultipleTransactions(const std::vector<CTransactionRef>& txns, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Package (more specific than just multiple transactions) acceptance. Package must be a child
     * with all of its unconfirmed parents, and topologically sorted.
     */
    PackageMempoolAcceptResult AcceptPackage(const Package& package, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    // All the intermediate state that gets passed between the various levels
    // of checking a given transaction.
    struct Workspace {
        explicit Workspace(const CTransactionRef& ptx) : m_ptx(ptx), m_hash(ptx->GetHash()) {}
        /** Txids of mempool transactions that this transaction directly conflicts with. */
        std::set<uint256> m_conflicts;
        /** Iterators to mempool entries that this transaction directly conflicts with. */
        CTxMemPool::setEntries m_iters_conflicting;
        /** Iterators to all mempool entries that would be replaced by this transaction, including
         * those it directly conflicts with and their descendants. */
        CTxMemPool::setEntries m_all_conflicting;
        /** All mempool ancestors of this transaction. */
        CTxMemPool::setEntries m_ancestors;
        /** Mempool entry constructed for this transaction. Constructed in PreChecks() but not
         * inserted into the mempool until Finalize(). */
        std::unique_ptr<CTxMemPoolEntry> m_entry;
        /** Pointers to the transactions that have been removed from the mempool and replaced by
         * this transaction, used to return to the MemPoolAccept caller. Only populated if
         * validation is successful and the original transactions are removed. */
        std::list<CTransactionRef> m_replaced_transactions;

        /** Virtual size of the transaction as used by the mempool, calculated using serialized size
         * of the transaction and sigops. */
        int64_t m_vsize;
        /** Fees paid by this transaction: total input amounts subtracted by total output amounts. */
        CAmount m_base_fees;
        /** Base fees + any fee delta set by the user with prioritisetransaction. */
        CAmount m_modified_fees;
        /** Total modified fees of all transactions being replaced. */
        CAmount m_conflicting_fees{0};
        /** Total virtual size of all transactions being replaced. */
        size_t m_conflicting_size{0};

        const CTransactionRef& m_ptx;
        /** Txid. */
        const uint256& m_hash;
        TxValidationState m_state;
        /** A temporary cache containing serialized transaction data for signature verification.
         * Reused across PolicyScriptChecks and ConsensusScriptChecks. */
        PrecomputedTransactionData m_precomputed_txdata;
    };

    // Run the policy checks on a given transaction, excluding any script checks.
    // Looks up inputs, calculates feerate, considers replacement, evaluates
    // package limits, etc. As this function can be invoked for "free" by a peer,
    // only tests that are fast should be done here (to avoid CPU DoS).
    bool PreChecks(ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Run checks for mempool replace-by-fee.
    bool ReplacementChecks(Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Enforce package mempool ancestor/descendant limits (distinct from individual
    // ancestor/descendant limits done in PreChecks).
    bool PackageMempoolChecks(const std::vector<CTransactionRef>& txns,
                              PackageValidationState& package_state) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Run the script checks using our policy flags. As this can be slow, we should
    // only invoke this on transactions that have otherwise passed policy checks.
    bool PolicyScriptChecks(const ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Re-run the script checks, using consensus flags, and try to cache the
    // result in the scriptcache. This should be done after
    // PolicyScriptChecks(). This requires that all inputs either be in our
    // utxo set or in the mempool.
    bool ConsensusScriptChecks(const ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Try to add the transaction to the mempool, removing any conflicts first.
    // Returns true if the transaction is in the mempool after any size
    // limiting is performed, false otherwise.
    bool Finalize(const ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Submit all transactions to the mempool and call ConsensusScriptChecks to add to the script
    // cache - should only be called after successful validation of all transactions in the package.
    // The package may end up partially-submitted after size limiting; returns true if all
    // transactions are successfully added to the mempool, false otherwise.
    bool SubmitPackage(const ATMPArgs& args, std::vector<Workspace>& workspaces, PackageValidationState& package_state,
                       std::map<const uint256, const MempoolAcceptResult>& results)
         EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Compare a package's feerate against minimum allowed.
    bool CheckFeeRate(size_t package_size, CAmount package_fee, TxValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_pool.cs)
    {
        AssertLockHeld(::cs_main);
        AssertLockHeld(m_pool.cs);
        CAmount mempoolRejectFee = m_pool.GetMinFee().GetFee(package_size);
        if (mempoolRejectFee > 0 && package_fee < mempoolRejectFee) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool min fee not met", strprintf("%d < %d", package_fee, mempoolRejectFee));
        }

        if (package_fee < m_pool.m_min_relay_feerate.GetFee(package_size)) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "min relay fee not met",
                                 strprintf("%d < %d", package_fee, m_pool.m_min_relay_feerate.GetFee(package_size)));
        }
        return true;
    }

private:
    CTxMemPool& m_pool;
    CCoinsViewCache m_view;
    CCoinsViewMemPool m_viewmempool;
    CCoinsView m_dummy;

    Chainstate& m_active_chainstate;

    // The package limits in effect at the time of invocation.
    const size_t m_limit_ancestors;
    const size_t m_limit_ancestor_size;
    // These may be modified while evaluating a transaction (eg to account for
    // in-mempool conflicts; see below).
    size_t m_limit_descendants;
    size_t m_limit_descendant_size;

    /** Whether the transaction(s) would replace any mempool transactions. If so, RBF rules apply. */
    bool m_rbf{false};
};

bool MemPoolAccept::PreChecks(ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransactionRef& ptx = ws.m_ptx;
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;

    // Copy/alias what we need out of args
    const int64_t nAcceptTime = args.m_accept_time;
    const bool bypass_limits = args.m_bypass_limits;
    std::vector<COutPoint>& coins_to_uncache = args.m_coins_to_uncache;
    const CChainParams& chainparams = args.m_chainparams;

    // Alias what we need out of ws
    TxValidationState& state = ws.m_state;
    std::unique_ptr<CTxMemPoolEntry>& entry = ws.m_entry;

    if (!CheckTransaction(tx, state)) {
        return false; // state filled in by CheckTransaction
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinbase");

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinstake");

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (m_pool.m_require_standard && !IsStandardTx(tx, m_pool.m_max_datacarrier_bytes, m_pool.m_permit_bare_multisig, m_pool.m_dust_relay_feerate, reason)) {
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, reason);
    }

    // Do not work on transactions that are too small.
    // A transaction with 1 segwit input and 1 P2WPHK output has non-witness size of 82 bytes.
    // Transactions smaller than this are not relayed to mitigate CVE-2017-12842 by not relaying
    // 64-byte transactions.
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) < MIN_STANDARD_TX_NONWITNESS_SIZE)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "tx-size-small");

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTxAtTip(*Assert(m_active_chainstate.m_chain.Tip()), tx)) {
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-final");
    }

    if (m_pool.exists(GenTxid::Wtxid(tx.GetWitnessHash()))) {
        // Exact transaction already exists in the mempool.
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-in-mempool");
    } else if (m_pool.exists(GenTxid::Txid(tx.GetHash()))) {
        // Transaction with the same non-witness data but different witness (same txid, different
        // wtxid) already exists in the mempool.
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-same-nonwitness-data-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    for (const CTxIn &txin : tx.vin)
    {
        const CTransaction* ptxConflicting = m_pool.GetConflictTx(txin.prevout);
        if (ptxConflicting) {
            if (!args.m_allow_replacement) {
                // Transaction conflicts with a mempool tx, but we're not allowing replacements.
                return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "bip125-replacement-disallowed");
            }
            if (!ws.m_conflicts.count(ptxConflicting->GetHash()))
            {
                // Transactions that don't explicitly signal replaceability are
                // *not* replaceable with the current logic, even if one of their
                // unconfirmed ancestors signals replaceability. This diverges
                // from BIP125's inherited signaling description (see CVE-2021-31876).
                // Applications relying on first-seen mempool behavior should
                // check all unconfirmed ancestors; otherwise an opt-in ancestor
                // might be replaced, causing removal of this descendant.
                //
                // If replaceability signaling is ignored due to node setting,
                // replacement is always allowed.
                if (!m_pool.m_full_rbf && !SignalsOptInRBF(*ptxConflicting)) {
                    return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "txn-mempool-conflict");
                }

                ws.m_conflicts.insert(ptxConflicting->GetHash());
            }
        }
    }

    LockPoints lp;
    m_view.SetBackend(m_viewmempool);

    const CCoinsViewCache& coins_cache = m_active_chainstate.CoinsTip();

    // do we already have it?
    for (size_t out = 0; out < tx.vout.size(); out++) {
        COutPoint outpoint(hash, out);
        bool had_coin_in_cache = coins_cache.HaveCoinInCache(outpoint);
        if (m_view.HaveCoin(outpoint)) {
            if (!had_coin_in_cache) {
                coins_to_uncache.push_back(outpoint);
            }
            return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
        }
    }

    // do all inputs exist?
    for (const CTxIn& txin : tx.vin) {
        if (!coins_cache.HaveCoinInCache(txin.prevout)) {
            coins_to_uncache.push_back(txin.prevout);
        }

        // Note: this call may add txin.prevout to the coins cache
        // (coins_cache.cacheCoins) by way of FetchCoin(). It should be removed
        // later (via coins_to_uncache) if this tx turns out to be invalid.
        if (!m_view.HaveCoin(txin.prevout)) {
            // Are inputs missing because we already have the tx?
            for (size_t out = 0; out < tx.vout.size(); out++) {
                // Optimistically just do efficient check of cache for outputs
                if (coins_cache.HaveCoinInCache(COutPoint(hash, out))) {
                    return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
                }
            }
            // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
        }
    }

    // This is const, but calls into the back end CoinsViews. The CCoinsViewDB at the bottom of the
    // hierarchy brings the best block into scope. See CCoinsViewDB::GetBestBlock().
    m_view.GetBestBlock();

    // we have all inputs cached now, so switch back to dummy (to protect
    // against bugs where we pull more inputs from disk that miss being added
    // to coins_to_uncache)
    m_view.SetBackend(m_dummy);

    assert(m_active_chainstate.m_blockman.LookupBlockIndex(m_view.GetBestBlock()) == m_active_chainstate.m_chain.Tip());

    // Only accept BIP68 sequence locked transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    // Pass in m_view which has all of the relevant inputs cached. Note that, since m_view's
    // backend was removed, it no longer pulls coins from the mempool.
    if (!CheckSequenceLocksAtTip(m_active_chainstate.m_chain.Tip(), m_view, tx, &lp)) {
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-BIP68-final");
    }

    // The mempool holds txs for the next block, so pass height+1 to CheckTxInputs
    if (!Consensus::CheckTxInputs(tx, state, m_view, m_active_chainstate.m_chain.Height() + 1, ws.m_base_fees)) {
        return false; // state filled in by CheckTxInputs
    }

    if (m_pool.m_require_standard && !AreInputsStandard(tx, m_view)) {
        return state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs");
    }

    // Check for non-standard witnesses.
    if (tx.HasWitness() && m_pool.m_require_standard && !IsWitnessStandard(tx, m_view)) {
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-witness-nonstandard");
    }

    int64_t nSigOpsCost = GetTransactionSigOpCost(tx, m_view, STANDARD_SCRIPT_VERIFY_FLAGS);

    dev::u256 txMinGasPrice = 0;

    //////////////////////////////////////////////////////////// // runebase
    if(!CheckOpSender(tx, chainparams, m_active_chainstate.m_chain.Height() + 1)){
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-invalid-sender");
    }
    if(tx.HasCreateOrCall()){

        if(!CheckSenderScript(m_view, tx)){
            return state.Invalid(TxValidationResult::TX_INVALID_SENDER_SCRIPT, "bad-txns-invalid-sender-script");
        }

        RunebaseDGP runebaseDGP(globalState.get(), m_active_chainstate, fGettingValuesDGP);
        uint64_t minGasPrice = runebaseDGP.getMinGasPrice(m_active_chainstate.m_chain.Tip()->nHeight + 1);
        uint64_t blockGasLimit = runebaseDGP.getBlockGasLimit(m_active_chainstate.m_chain.Tip()->nHeight + 1);
        size_t count = 0;
        for(const CTxOut& o : tx.vout)
            count += o.scriptPubKey.HasOpCreate() || o.scriptPubKey.HasOpCall() ? 1 : 0;
        unsigned int contractflags = GetContractScriptFlags(m_active_chainstate.m_chain.Height() + 1, chainparams.GetConsensus());
        RunebaseTxConverter converter(tx, m_active_chainstate, &m_pool, NULL, NULL, contractflags);
        ExtractRunebaseTX resultConverter;
        if(!converter.extractionRunebaseTransactions(resultConverter)){
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-bad-contract-format", "AcceptToMempool(): Contract transaction of the wrong format");
        }
        std::vector<RunebaseTransaction> runebaseTransactions = resultConverter.first;
        std::vector<EthTransactionParams> runebaseETP = resultConverter.second;

        dev::u256 sumGas = dev::u256(0);
        dev::u256 gasAllTxs = dev::u256(0);
        for(RunebaseTransaction runebaseTransaction : runebaseTransactions){
            sumGas += runebaseTransaction.gas() * runebaseTransaction.gasPrice();

            if(sumGas > dev::u256(INT64_MAX)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-gas-stipend-overflow", "AcceptToMempool(): Transaction's gas stipend overflows");
            }

            if(sumGas > dev::u256(ws.m_base_fees)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-notenough", "AcceptToMempool(): Transaction fee does not cover the gas stipend");
            }

            if(txMinGasPrice != 0) {
                txMinGasPrice = std::min(txMinGasPrice, runebaseTransaction.gasPrice());
            } else {
                txMinGasPrice = runebaseTransaction.gasPrice();
            }
            VersionVM v = runebaseTransaction.getVersion();
            if(v.format!=0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-version-format", "AcceptToMempool(): Contract execution uses unknown version format");
            if(v.rootVM != 1)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-version-rootvm", "AcceptToMempool(): Contract execution uses unknown root VM");
            if(v.vmVersion != 0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-version-vmversion", "AcceptToMempool(): Contract execution uses unknown VM version");
            if(v.flagOptions != 0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-version-flags", "AcceptToMempool(): Contract execution uses unknown flag options");

            //check gas limit is not less than minimum mempool gas limit
            if(runebaseTransaction.gas() < gArgs.GetIntArg("-minmempoolgaslimit", MEMPOOL_MIN_GAS_LIMIT))
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-too-little-mempool-gas", "AcceptToMempool(): Contract execution has lower gas limit than allowed to accept into mempool");

            //check gas limit is not less than minimum gas limit (unless it is a no-exec tx)
            if(runebaseTransaction.gas() < MINIMUM_GAS_LIMIT && v.rootVM != 0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-too-little-gas", "AcceptToMempool(): Contract execution has lower gas limit than allowed");

            if(runebaseTransaction.gas() > UINT32_MAX)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-too-much-gas", "AcceptToMempool(): Contract execution can not specify greater gas limit than can fit in 32-bits");

            gasAllTxs += runebaseTransaction.gas();
            if(gasAllTxs > dev::u256(blockGasLimit))
                return state.Invalid(TxValidationResult::TX_GAS_EXCEEDS_LIMIT, "bad-txns-gas-exceeds-blockgaslimit");

            //don't allow less than DGP set minimum gas price to prevent MPoS greedy mining/spammers
            if(v.rootVM!=0 && (uint64_t)runebaseTransaction.gasPrice() < minGasPrice)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-low-gas-price", "AcceptToMempool(): Contract execution has lower gas price than allowed");
        }

        if(!CheckMinGasPrice(runebaseETP, minGasPrice))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-small-gasprice");

        if(count > runebaseTransactions.size())
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-incorrect-format");
    }
    ////////////////////////////////////////////////////////////


    // ws.m_modified_fees includes any fee deltas from PrioritiseTransaction
    ws.m_modified_fees = ws.m_base_fees;
    m_pool.ApplyDelta(hash, ws.m_modified_fees);

    // Keep track of transactions that spend a coinbase, which we re-scan
    // during reorgs to ensure coinbaseMaturity is still met.
    bool fSpendsCoinbase = false;
    for (const CTxIn &txin : tx.vin) {
        const Coin &coin = m_view.AccessCoin(txin.prevout);
        if (coin.IsCoinBase() || coin.IsCoinStake()) {
            fSpendsCoinbase = true;
            break;
        }
    }

    entry.reset(new CTxMemPoolEntry(ptx, ws.m_base_fees, nAcceptTime, m_active_chainstate.m_chain.Height(),
            fSpendsCoinbase, nSigOpsCost, lp, CAmount(txMinGasPrice)));
    ws.m_vsize = entry->GetTxSize();

    if (nSigOpsCost > dgpMaxTxSigOps)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "bad-txns-too-many-sigops",
                strprintf("%d", nSigOpsCost));

    // No individual transactions are allowed below the min relay feerate and mempool min feerate except from
    // disconnected blocks and transactions in a package. Package transactions will be checked using
    // package feerate later.
    if (!bypass_limits && !args.m_package_feerates && !CheckFeeRate(ws.m_vsize, ws.m_modified_fees, state)) return false;

    ws.m_iters_conflicting = m_pool.GetIterSet(ws.m_conflicts);
    // Calculate in-mempool ancestors, up to a limit.
    if (ws.m_conflicts.size() == 1) {
        // In general, when we receive an RBF transaction with mempool conflicts, we want to know whether we
        // would meet the chain limits after the conflicts have been removed. However, there isn't a practical
        // way to do this short of calculating the ancestor and descendant sets with an overlay cache of
        // changed mempool entries. Due to both implementation and runtime complexity concerns, this isn't
        // very realistic, thus we only ensure a limited set of transactions are RBF'able despite mempool
        // conflicts here. Importantly, we need to ensure that some transactions which were accepted using
        // the below carve-out are able to be RBF'ed, without impacting the security the carve-out provides
        // for off-chain contract systems (see link in the comment below).
        //
        // Specifically, the subset of RBF transactions which we allow despite chain limits are those which
        // conflict directly with exactly one other transaction (but may evict children of said transaction),
        // and which are not adding any new mempool dependencies. Note that the "no new mempool dependencies"
        // check is accomplished later, so we don't bother doing anything about it here, but if our
        // policy changes, we may need to move that check to here instead of removing it wholesale.
        //
        // Such transactions are clearly not merging any existing packages, so we are only concerned with
        // ensuring that (a) no package is growing past the package size (not count) limits and (b) we are
        // not allowing something to effectively use the (below) carve-out spot when it shouldn't be allowed
        // to.
        //
        // To check these we first check if we meet the RBF criteria, above, and increment the descendant
        // limits by the direct conflict and its descendants (as these are recalculated in
        // CalculateMempoolAncestors by assuming the new transaction being added is a new descendant, with no
        // removals, of each parent's existing dependent set). The ancestor count limits are unmodified (as
        // the ancestor limits should be the same for both our new transaction and any conflicts).
        // We don't bother incrementing m_limit_descendants by the full removal count as that limit never comes
        // into force here (as we're only adding a single transaction).
        assert(ws.m_iters_conflicting.size() == 1);
        CTxMemPool::txiter conflict = *ws.m_iters_conflicting.begin();

        m_limit_descendants += 1;
        m_limit_descendant_size += conflict->GetSizeWithDescendants();
    }

    std::string errString;
    if (!m_pool.CalculateMemPoolAncestors(*entry, ws.m_ancestors, m_limit_ancestors, m_limit_ancestor_size, m_limit_descendants, m_limit_descendant_size, errString)) {
        ws.m_ancestors.clear();
        // If CalculateMemPoolAncestors fails second time, we want the original error string.
        std::string dummy_err_string;
        // Contracting/payment channels CPFP carve-out:
        // If the new transaction is relatively small (up to 40k weight)
        // and has at most one ancestor (ie ancestor limit of 2, including
        // the new transaction), allow it if its parent has exactly the
        // descendant limit descendants.
        //
        // This allows protocols which rely on distrusting counterparties
        // being able to broadcast descendants of an unconfirmed transaction
        // to be secure by simply only having two immediately-spendable
        // outputs - one for each counterparty. For more info on the uses for
        // this, see https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-November/016518.html
        if (ws.m_vsize > EXTRA_DESCENDANT_TX_SIZE_LIMIT ||
                !m_pool.CalculateMemPoolAncestors(*entry, ws.m_ancestors, 2, m_limit_ancestor_size, m_limit_descendants + 1, m_limit_descendant_size + EXTRA_DESCENDANT_TX_SIZE_LIMIT, dummy_err_string)) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too-long-mempool-chain", errString);
        }
    }

    // A transaction that spends outputs that would be replaced by it is invalid. Now
    // that we have the set of all ancestors we can detect this
    // pathological case by making sure ws.m_conflicts and ws.m_ancestors don't
    // intersect.
    if (const auto err_string{EntriesAndTxidsDisjoint(ws.m_ancestors, ws.m_conflicts, hash)}) {
        // We classify this as a consensus error because a transaction depending on something it
        // conflicts with would be inconsistent.
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-spends-conflicting-tx", *err_string);
    }

    m_rbf = !ws.m_conflicts.empty();
    return true;
}

bool MemPoolAccept::ReplacementChecks(Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);

    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;
    TxValidationState& state = ws.m_state;

    CFeeRate newFeeRate(ws.m_modified_fees, ws.m_vsize);
    // Enforce Rule #6. The replacement transaction must have a higher feerate than its direct conflicts.
    // - The motivation for this check is to ensure that the replacement transaction is preferable for
    //   block-inclusion, compared to what would be removed from the mempool.
    // - This logic predates ancestor feerate-based transaction selection, which is why it doesn't
    //   consider feerates of descendants.
    // - Note: Ancestor feerate-based transaction selection has made this comparison insufficient to
    //   guarantee that this is incentive-compatible for miners, because it is possible for a
    //   descendant transaction of a direct conflict to pay a higher feerate than the transaction that
    //   might replace them, under these rules.
    if (const auto err_string{PaysMoreThanConflicts(ws.m_iters_conflicting, newFeeRate, hash)}) {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee", *err_string);
    }

    // Calculate all conflicting entries and enforce Rule #5.
    if (const auto err_string{GetEntriesForConflicts(tx, m_pool, ws.m_iters_conflicting, ws.m_all_conflicting)}) {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY,
                             "too many potential replacements", *err_string);
    }
    // Enforce Rule #2.
    if (const auto err_string{HasNoNewUnconfirmed(tx, m_pool, ws.m_iters_conflicting)}) {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY,
                             "replacement-adds-unconfirmed", *err_string);
    }
    // Check if it's economically rational to mine this transaction rather than the ones it
    // replaces and pays for its own relay fees. Enforce Rules #3 and #4.
    for (CTxMemPool::txiter it : ws.m_all_conflicting) {
        ws.m_conflicting_fees += it->GetModifiedFee();
        ws.m_conflicting_size += it->GetTxSize();
    }
    if (const auto err_string{PaysForRBF(ws.m_conflicting_fees, ws.m_modified_fees, ws.m_vsize,
                                         m_pool.m_incremental_relay_feerate, hash)}) {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee", *err_string);
    }
    return true;
}

bool MemPoolAccept::PackageMempoolChecks(const std::vector<CTransactionRef>& txns,
                                         PackageValidationState& package_state)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);

    // CheckPackageLimits expects the package transactions to not already be in the mempool.
    assert(std::all_of(txns.cbegin(), txns.cend(), [this](const auto& tx)
                       { return !m_pool.exists(GenTxid::Txid(tx->GetHash()));}));

    std::string err_string;
    if (!m_pool.CheckPackageLimits(txns, m_limit_ancestors, m_limit_ancestor_size, m_limit_descendants,
                                   m_limit_descendant_size, err_string)) {
        // This is a package-wide error, separate from an individual transaction error.
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package-mempool-limits", err_string);
    }
   return true;
}

bool MemPoolAccept::PolicyScriptChecks(const ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction& tx = *ws.m_ptx;
    TxValidationState& state = ws.m_state;

    constexpr unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;

    // Check input scripts and signatures.
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.
    if (!CheckInputScripts(tx, state, m_view, scriptVerifyFlags, true, false, ws.m_precomputed_txdata)) {
        // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
        // need to turn both off, and compare against just turning off CLEANSTACK
        // to see if the failure is specifically due to witness validation.
        TxValidationState state_dummy; // Want reported failures to be from first CheckInputScripts
        if (!tx.HasWitness() && CheckInputScripts(tx, state_dummy, m_view, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, false, ws.m_precomputed_txdata) &&
                !CheckInputScripts(tx, state_dummy, m_view, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, false, ws.m_precomputed_txdata)) {
            // Only the witness is missing, so the transaction itself may be fine.
            state.Invalid(TxValidationResult::TX_WITNESS_STRIPPED,
                    state.GetRejectReason(), state.GetDebugMessage());
        }
        return false; // state filled in by CheckInputScripts
    }

    return true;
}

bool MemPoolAccept::ConsensusScriptChecks(const ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;
    TxValidationState& state = ws.m_state;

    // Check again against the current block tip's script verification
    // flags to cache our script execution flags. This is, of course,
    // useless if the next block has different script flags from the
    // previous one, but because the cache tracks script flags for us it
    // will auto-invalidate and we'll just have a few blocks of extra
    // misses on soft-fork activation.
    //
    // This is also useful in case of bugs in the standard flags that cause
    // transactions to pass as valid when they're actually invalid. For
    // instance the STRICTENC flag was incorrectly allowing certain
    // CHECKSIG NOT scripts to pass, even though they were invalid.
    //
    // There is a similar check in CreateNewBlock() to prevent creating
    // invalid blocks (using TestBlockValidity), however allowing such
    // transactions into the mempool can be exploited as a DoS attack.
    unsigned int currentBlockScriptVerifyFlags{GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), m_active_chainstate.m_chainman)};
    if (!CheckInputsFromMempoolAndCache(tx, state, m_view, m_pool, currentBlockScriptVerifyFlags,
                                        ws.m_precomputed_txdata, m_active_chainstate.CoinsTip())) {
        LogPrintf("BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block but not STANDARD flags %s, %s\n", hash.ToString(), state.ToString());
        return Assume(false);
    }

    return true;
}

bool MemPoolAccept::Finalize(const ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;
    TxValidationState& state = ws.m_state;
    const bool bypass_limits = args.m_bypass_limits;

    std::unique_ptr<CTxMemPoolEntry>& entry = ws.m_entry;

    // Remove conflicting transactions from the mempool
    for (CTxMemPool::txiter it : ws.m_all_conflicting)
    {
        LogPrint(BCLog::MEMPOOL, "replacing tx %s with %s for %s additional fees, %d delta bytes\n",
                it->GetTx().GetHash().ToString(),
                hash.ToString(),
                FormatMoney(ws.m_modified_fees - ws.m_conflicting_fees),
                (int)entry->GetTxSize() - (int)ws.m_conflicting_size);
        ws.m_replaced_transactions.push_back(it->GetSharedTx());
    }
    m_pool.RemoveStaged(ws.m_all_conflicting, false, MemPoolRemovalReason::REPLACED);

    // This transaction should only count for fee estimation if:
    // - it's not being re-added during a reorg which bypasses typical mempool fee limits
    // - the node is not behind
    // - the transaction is not dependent on any other transactions in the mempool
    // - it's not part of a package. Since package relay is not currently supported, this
    // transaction has not necessarily been accepted to miners' mempools.
    bool validForFeeEstimation = !bypass_limits && !args.m_package_submission && IsCurrentForFeeEstimation(m_active_chainstate) && m_pool.HasNoInputsOf(tx);

    //////////////////////////////////////////////////////////////// // runebase
    // Add memory address index
    if (fAddressIndex)
    {
        m_pool.addAddressIndex(*entry, m_view);
        m_pool.addSpentIndex(*entry, m_view);
    }
    ////////////////////////////////////////////////////////////////

    // Store transaction in memory
    m_pool.addUnchecked(*entry, ws.m_ancestors, validForFeeEstimation);

    // trim mempool and check if tx was trimmed
    // If we are validating a package, don't trim here because we could evict a previous transaction
    // in the package. LimitMempoolSize() should be called at the very end to make sure the mempool
    // is still within limits and package submission happens atomically.
    if (!args.m_package_submission && !bypass_limits) {
        LimitMempoolSize(m_pool, m_active_chainstate.CoinsTip());
        if (!m_pool.exists(GenTxid::Txid(hash)))
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
    }
    return true;
}

bool MemPoolAccept::SubmitPackage(const ATMPArgs& args, std::vector<Workspace>& workspaces,
                                  PackageValidationState& package_state,
                                  std::map<const uint256, const MempoolAcceptResult>& results)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    // Sanity check: none of the transactions should be in the mempool, and none of the transactions
    // should have a same-txid-different-witness equivalent in the mempool.
    assert(std::all_of(workspaces.cbegin(), workspaces.cend(), [this](const auto& ws){
        return !m_pool.exists(GenTxid::Txid(ws.m_ptx->GetHash())); }));

    bool all_submitted = true;
    // ConsensusScriptChecks adds to the script cache and is therefore consensus-critical;
    // CheckInputsFromMempoolAndCache asserts that transactions only spend coins available from the
    // mempool or UTXO set. Submit each transaction to the mempool immediately after calling
    // ConsensusScriptChecks to make the outputs available for subsequent transactions.
    for (Workspace& ws : workspaces) {
        if (!ConsensusScriptChecks(args, ws)) {
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            // Since PolicyScriptChecks() passed, this should never fail.
            Assume(false);
            all_submitted = false;
            package_state.Invalid(PackageValidationResult::PCKG_MEMPOOL_ERROR,
                                  strprintf("BUG! PolicyScriptChecks succeeded but ConsensusScriptChecks failed: %s",
                                            ws.m_ptx->GetHash().ToString()));
        }

        // Re-calculate mempool ancestors to call addUnchecked(). They may have changed since the
        // last calculation done in PreChecks, since package ancestors have already been submitted.
        std::string unused_err_string;
        if(!m_pool.CalculateMemPoolAncestors(*ws.m_entry, ws.m_ancestors, m_limit_ancestors,
                                             m_limit_ancestor_size, m_limit_descendants,
                                             m_limit_descendant_size, unused_err_string)) {
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            // Since PreChecks() and PackageMempoolChecks() both enforce limits, this should never fail.
            Assume(false);
            all_submitted = false;
            package_state.Invalid(PackageValidationResult::PCKG_MEMPOOL_ERROR,
                                  strprintf("BUG! Mempool ancestors or descendants were underestimated: %s",
                                            ws.m_ptx->GetHash().ToString()));
        }
        // If we call LimitMempoolSize() for each individual Finalize(), the mempool will not take
        // the transaction's descendant feerate into account because it hasn't seen them yet. Also,
        // we risk evicting a transaction that a subsequent package transaction depends on. Instead,
        // allow the mempool to temporarily bypass limits, the maximum package size) while
        // submitting transactions individually and then trim at the very end.
        if (!Finalize(args, ws)) {
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            // Since LimitMempoolSize() won't be called, this should never fail.
            Assume(false);
            all_submitted = false;
            package_state.Invalid(PackageValidationResult::PCKG_MEMPOOL_ERROR,
                                  strprintf("BUG! Adding to mempool failed: %s", ws.m_ptx->GetHash().ToString()));
        }
    }

    // It may or may not be the case that all the transactions made it into the mempool. Regardless,
    // make sure we haven't exceeded max mempool size.
    LimitMempoolSize(m_pool, m_active_chainstate.CoinsTip());

    // Find the wtxids of the transactions that made it into the mempool. Allow partial submission,
    // but don't report success unless they all made it into the mempool.
    for (Workspace& ws : workspaces) {
        if (m_pool.exists(GenTxid::Wtxid(ws.m_ptx->GetWitnessHash()))) {
            results.emplace(ws.m_ptx->GetWitnessHash(),
                MempoolAcceptResult::Success(std::move(ws.m_replaced_transactions), ws.m_vsize, ws.m_base_fees));
            GetMainSignals().TransactionAddedToMempool(ws.m_ptx, m_pool.GetAndIncrementSequence());
        } else {
            all_submitted = false;
            ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
        }
    }
    return all_submitted;
}

MempoolAcceptResult MemPoolAccept::AcceptSingleTransaction(const CTransactionRef& ptx, ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    LOCK(m_pool.cs); // mempool "read lock" (held through GetMainSignals().TransactionAddedToMempool())

    Workspace ws(ptx);

    if (!PreChecks(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    if (m_rbf && !ReplacementChecks(ws)) return MempoolAcceptResult::Failure(ws.m_state);

    // Perform the inexpensive checks first and avoid hashing and signature verification unless
    // those checks pass, to mitigate CPU exhaustion denial-of-service attacks.
    if (!PolicyScriptChecks(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    if (!ConsensusScriptChecks(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    // Tx was accepted, but not added
    if (args.m_test_accept) {
        return MempoolAcceptResult::Success(std::move(ws.m_replaced_transactions), ws.m_vsize, ws.m_base_fees);
    }

    if (!Finalize(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    GetMainSignals().TransactionAddedToMempool(ptx, m_pool.GetAndIncrementSequence());

    return MempoolAcceptResult::Success(std::move(ws.m_replaced_transactions), ws.m_vsize, ws.m_base_fees);
}

PackageMempoolAcceptResult MemPoolAccept::AcceptMultipleTransactions(const std::vector<CTransactionRef>& txns, ATMPArgs& args)
{
    AssertLockHeld(cs_main);

    // These context-free package limits can be done before taking the mempool lock.
    PackageValidationState package_state;
    if (!CheckPackage(txns, package_state)) return PackageMempoolAcceptResult(package_state, {});

    std::vector<Workspace> workspaces{};
    workspaces.reserve(txns.size());
    std::transform(txns.cbegin(), txns.cend(), std::back_inserter(workspaces),
                   [](const auto& tx) { return Workspace(tx); });
    std::map<const uint256, const MempoolAcceptResult> results;

    LOCK(m_pool.cs);

    // Do all PreChecks first and fail fast to avoid running expensive script checks when unnecessary.
    for (Workspace& ws : workspaces) {
        if (!PreChecks(args, ws)) {
            package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
            // Exit early to avoid doing pointless work. Update the failed tx result; the rest are unfinished.
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state, std::move(results));
        }
        // Make the coins created by this transaction available for subsequent transactions in the
        // package to spend. Since we already checked conflicts in the package and we don't allow
        // replacements, we don't need to track the coins spent. Note that this logic will need to be
        // updated if package replace-by-fee is allowed in the future.
        assert(!args.m_allow_replacement);
        m_viewmempool.PackageAddTransaction(ws.m_ptx);
    }

    // Transactions must meet two minimum feerates: the mempool minimum fee and min relay fee.
    // For transactions consisting of exactly one child and its parents, it suffices to use the
    // package feerate (total modified fees / total virtual size) to check this requirement.
    const auto m_total_vsize = std::accumulate(workspaces.cbegin(), workspaces.cend(), int64_t{0},
        [](int64_t sum, auto& ws) { return sum + ws.m_vsize; });
    const auto m_total_modified_fees = std::accumulate(workspaces.cbegin(), workspaces.cend(), CAmount{0},
        [](CAmount sum, auto& ws) { return sum + ws.m_modified_fees; });
    const CFeeRate package_feerate(m_total_modified_fees, m_total_vsize);
    TxValidationState placeholder_state;
    if (args.m_package_feerates &&
        !CheckFeeRate(m_total_vsize, m_total_modified_fees, placeholder_state)) {
        package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package-fee-too-low");
        return PackageMempoolAcceptResult(package_state, package_feerate, {});
    }

    // Apply package mempool ancestor/descendant limits. Skip if there is only one transaction,
    // because it's unnecessary. Also, CPFP carve out can increase the limit for individual
    // transactions, but this exemption is not extended to packages in CheckPackageLimits().
    std::string err_string;
    if (txns.size() > 1 && !PackageMempoolChecks(txns, package_state)) {
        return PackageMempoolAcceptResult(package_state, package_feerate, std::move(results));
    }

    for (Workspace& ws : workspaces) {
        if (!PolicyScriptChecks(args, ws)) {
            // Exit early to avoid doing pointless work. Update the failed tx result; the rest are unfinished.
            package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state, package_feerate, std::move(results));
        }
        if (args.m_test_accept) {
            // When test_accept=true, transactions that pass PolicyScriptChecks are valid because there are
            // no further mempool checks (passing PolicyScriptChecks implies passing ConsensusScriptChecks).
            results.emplace(ws.m_ptx->GetWitnessHash(),
                            MempoolAcceptResult::Success(std::move(ws.m_replaced_transactions),
                                                         ws.m_vsize, ws.m_base_fees));
        }
    }

    if (args.m_test_accept) return PackageMempoolAcceptResult(package_state, package_feerate, std::move(results));

    if (!SubmitPackage(args, workspaces, package_state, results)) {
        // PackageValidationState filled in by SubmitPackage().
        return PackageMempoolAcceptResult(package_state, package_feerate, std::move(results));
    }

    return PackageMempoolAcceptResult(package_state, package_feerate, std::move(results));
}

PackageMempoolAcceptResult MemPoolAccept::AcceptPackage(const Package& package, ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    PackageValidationState package_state;

    // Check that the package is well-formed. If it isn't, we won't try to validate any of the
    // transactions and thus won't return any MempoolAcceptResults, just a package-wide error.

    // Context-free package checks.
    if (!CheckPackage(package, package_state)) return PackageMempoolAcceptResult(package_state, {});

    // All transactions in the package must be a parent of the last transaction. This is just an
    // opportunity for us to fail fast on a context-free check without taking the mempool lock.
    if (!IsChildWithParents(package)) {
        package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-child-with-parents");
        return PackageMempoolAcceptResult(package_state, {});
    }

    // IsChildWithParents() guarantees the package is > 1 transactions.
    assert(package.size() > 1);
    // The package must be 1 child with all of its unconfirmed parents. The package is expected to
    // be sorted, so the last transaction is the child.
    const auto& child = package.back();
    std::unordered_set<uint256, SaltedTxidHasher> unconfirmed_parent_txids;
    std::transform(package.cbegin(), package.cend() - 1,
                   std::inserter(unconfirmed_parent_txids, unconfirmed_parent_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });

    // All child inputs must refer to a preceding package transaction or a confirmed UTXO. The only
    // way to verify this is to look up the child's inputs in our current coins view (not including
    // mempool), and enforce that all parents not present in the package be available at chain tip.
    // Since this check can bring new coins into the coins cache, keep track of these coins and
    // uncache them if we don't end up submitting this package to the mempool.
    const CCoinsViewCache& coins_tip_cache = m_active_chainstate.CoinsTip();
    for (const auto& input : child->vin) {
        if (!coins_tip_cache.HaveCoinInCache(input.prevout)) {
            args.m_coins_to_uncache.push_back(input.prevout);
        }
    }
    // Using the MemPoolAccept m_view cache allows us to look up these same coins faster later.
    // This should be connecting directly to CoinsTip, not to m_viewmempool, because we specifically
    // require inputs to be confirmed if they aren't in the package.
    m_view.SetBackend(m_active_chainstate.CoinsTip());
    const auto package_or_confirmed = [this, &unconfirmed_parent_txids](const auto& input) {
         return unconfirmed_parent_txids.count(input.prevout.hash) > 0 || m_view.HaveCoin(input.prevout);
    };
    if (!std::all_of(child->vin.cbegin(), child->vin.cend(), package_or_confirmed)) {
        package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-child-with-unconfirmed-parents");
        return PackageMempoolAcceptResult(package_state, {});
    }
    // Protect against bugs where we pull more inputs from disk that miss being added to
    // coins_to_uncache. The backend will be connected again when needed in PreChecks.
    m_view.SetBackend(m_dummy);

    LOCK(m_pool.cs);
    std::map<const uint256, const MempoolAcceptResult> results;
    // Node operators are free to set their mempool policies however they please, nodes may receive
    // transactions in different orders, and malicious counterparties may try to take advantage of
    // policy differences to pin or delay propagation of transactions. As such, it's possible for
    // some package transaction(s) to already be in the mempool, and we don't want to reject the
    // entire package in that case (as that could be a censorship vector). De-duplicate the
    // transactions that are already in the mempool, and only call AcceptMultipleTransactions() with
    // the new transactions. This ensures we don't double-count transaction counts and sizes when
    // checking ancestor/descendant limits, or double-count transaction fees for fee-related policy.
    ATMPArgs single_args = ATMPArgs::SingleInPackageAccept(args);
    bool quit_early{false};
    std::vector<CTransactionRef> txns_new;
    for (const auto& tx : package) {
        const auto& wtxid = tx->GetWitnessHash();
        const auto& txid = tx->GetHash();
        // There are 3 possibilities: already in mempool, same-txid-diff-wtxid already in mempool,
        // or not in mempool. An already confirmed tx is treated as one not in mempool, because all
        // we know is that the inputs aren't available.
        if (m_pool.exists(GenTxid::Wtxid(wtxid))) {
            // Exact transaction already exists in the mempool.
            auto iter = m_pool.GetIter(txid);
            assert(iter != std::nullopt);
            results.emplace(wtxid, MempoolAcceptResult::MempoolTx(iter.value()->GetTxSize(), iter.value()->GetFee()));
        } else if (m_pool.exists(GenTxid::Txid(txid))) {
            // Transaction with the same non-witness data but different witness (same txid,
            // different wtxid) already exists in the mempool.
            //
            // We don't allow replacement transactions right now, so just swap the package
            // transaction for the mempool one. Note that we are ignoring the validity of the
            // package transaction passed in.
            // TODO: allow witness replacement in packages.
            auto iter = m_pool.GetIter(txid);
            assert(iter != std::nullopt);
            // Provide the wtxid of the mempool tx so that the caller can look it up in the mempool.
            results.emplace(wtxid, MempoolAcceptResult::MempoolTxDifferentWitness(iter.value()->GetTx().GetWitnessHash()));
        } else {
            // Transaction does not already exist in the mempool.
            // Try submitting the transaction on its own.
            const auto single_res = AcceptSingleTransaction(tx, single_args);
            if (single_res.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                // The transaction succeeded on its own and is now in the mempool. Don't include it
                // in package validation, because its fees should only be "used" once.
                assert(m_pool.exists(GenTxid::Wtxid(wtxid)));
                results.emplace(wtxid, single_res);
            } else if (single_res.m_state.GetResult() != TxValidationResult::TX_MEMPOOL_POLICY &&
                       single_res.m_state.GetResult() != TxValidationResult::TX_MISSING_INPUTS) {
                // Package validation policy only differs from individual policy in its evaluation
                // of feerate. For example, if a transaction fails here due to violation of a
                // consensus rule, the result will not change when it is submitted as part of a
                // package. To minimize the amount of repeated work, unless the transaction fails
                // due to feerate or missing inputs (its parent is a previous transaction in the
                // package that failed due to feerate), don't run package validation. Note that this
                // decision might not make sense if different types of packages are allowed in the
                // future.  Continue individually validating the rest of the transactions, because
                // some of them may still be valid.
                quit_early = true;
            } else {
                txns_new.push_back(tx);
            }
        }
    }

    // Nothing to do if the entire package has already been submitted.
    if (quit_early || txns_new.empty()) {
        // No package feerate when no package validation was done.
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }
    // Validate the (deduplicated) transactions as a package.
    auto submission_result = AcceptMultipleTransactions(txns_new, args);
    // Include already-in-mempool transaction results in the final result.
    for (const auto& [wtxid, mempoolaccept_res] : results) {
        submission_result.m_tx_results.emplace(wtxid, mempoolaccept_res);
    }
    if (submission_result.m_state.IsValid()) assert(submission_result.m_package_feerate.has_value());
    return submission_result;
}

} // anon namespace

MempoolAcceptResult AcceptToMemoryPool(Chainstate& active_chainstate, const CTransactionRef& tx,
                                       int64_t accept_time, bool bypass_limits, bool test_accept)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    const CChainParams& chainparams{active_chainstate.m_params};
    assert(active_chainstate.GetMempool() != nullptr);
    CTxMemPool& pool{*active_chainstate.GetMempool()};

    std::vector<COutPoint> coins_to_uncache;
    auto args = MemPoolAccept::ATMPArgs::SingleAccept(chainparams, accept_time, bypass_limits, coins_to_uncache, test_accept);
    const MempoolAcceptResult result = MemPoolAccept(pool, active_chainstate).AcceptSingleTransaction(tx, args);
    if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        // Remove coins that were not present in the coins cache before calling
        // AcceptSingleTransaction(); this is to prevent memory DoS in case we receive a large
        // number of invalid transactions that attempt to overrun the in-memory coins cache
        // (`CCoinsViewCache::cacheCoins`).

        for (const COutPoint& hashTx : coins_to_uncache)
            active_chainstate.CoinsTip().Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    BlockValidationState state_dummy;
    active_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    return result;
}

PackageMempoolAcceptResult ProcessNewPackage(Chainstate& active_chainstate, CTxMemPool& pool,
                                                   const Package& package, bool test_accept)
{
    AssertLockHeld(cs_main);
    assert(!package.empty());
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));

    std::vector<COutPoint> coins_to_uncache;
    const CChainParams& chainparams = active_chainstate.m_params;
    const auto result = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        if (test_accept) {
            auto args = MemPoolAccept::ATMPArgs::PackageTestAccept(chainparams, GetTime(), coins_to_uncache);
            return MemPoolAccept(pool, active_chainstate).AcceptMultipleTransactions(package, args);
        } else {
            auto args = MemPoolAccept::ATMPArgs::PackageChildWithParents(chainparams, GetTime(), coins_to_uncache);
            return MemPoolAccept(pool, active_chainstate).AcceptPackage(package, args);
        }
    }();

    // Uncache coins pertaining to transactions that were not submitted to the mempool.
    if (test_accept || result.m_state.IsInvalid()) {
        for (const COutPoint& hashTx : coins_to_uncache) {
            active_chainstate.CoinsTip().Uncache(hashTx);
        }
    }
    // Ensure the coins cache is still within limits.
    BlockValidationState state_dummy;
    active_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    return result;
}

bool IsConfirmedInNPrevBlocks(const CDiskTxPos& txindex, const CBlockIndex* pindexFrom, int nMaxDepth, int& nActualDepth)
{
    for (const CBlockIndex* pindex = pindexFrom; pindex && pindexFrom->nHeight - pindex->nHeight < nMaxDepth; pindex = pindex->pprev)
    {
        if (pindex->nDataPos == txindex.nPos && pindex->nFile == txindex.nFile)
        {
            nActualDepth = pindexFrom->nHeight - pindex->nHeight;
            return true;
        }
    }
    return false;
}

bool CheckHeaderPoW(const CBlockHeader& block, const Consensus::Params& consensusParams)
{
    // Check for proof of work block header
    return CheckProofOfWork(block.GetHash(), block.nBits, consensusParams);
}

bool CheckHeaderPoS(const CBlockHeader& block, const Consensus::Params& consensusParams, Chainstate& chainstate)
{
    LOCK(cs_main);
    // Check for proof of stake block header
    // Get prev block index
    BlockMap::iterator mi = chainstate.m_blockman.m_block_index.find(block.hashPrevBlock);
    if (mi == chainstate.m_blockman.m_block_index.end())
        return false;

    // Check the kernel hash
    CBlockIndex* pindexPrev = &((*mi).second);

    if(pindexPrev->nHeight >= consensusParams.nEnableHeaderSignatureHeight && !CheckRecoveredPubKeyFromBlockSignature(pindexPrev, block, chainstate.CoinsTip(), chainstate.m_chain)) {
        return error("Failed signature check");
    }

    return CheckKernel(pindexPrev, block.nBits, block.StakeTime(), block.prevoutStake, chainstate.CoinsTip(), chainstate.m_chain);
}

bool CheckHeaderProof(const CBlockHeader& block, const Consensus::Params& consensusParams, Chainstate& chainstate){
    if(block.IsProofOfWork()){
        return CheckHeaderPoW(block, consensusParams);
    }
    if(block.IsProofOfStake()){
        return CheckHeaderPoS(block, consensusParams, chainstate);
    }
    return false;
}

bool CheckIndexProof(const CBlockIndex& block, const Consensus::Params& consensusParams)
{
    // Get the hash of the proof
    // After validating the PoS block the computed hash proof is saved in the block index, which is used to check the index
    uint256 hashProof = block.IsProofOfWork() ? block.GetBlockHash() : block.hashProof;
    // Check for proof after the hash proof is computed
    if(block.IsProofOfStake()){
        //blocks are loaded out of order, so checking PoS kernels here is not practical
        return true; //CheckKernel(block.pprev, block.nBits, block.nTime, block.prevoutStake);
    }else{
        return CheckProofOfWork(hashProof, block.nBits, consensusParams);
    }
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    if(nHeight == 1)
        return 40000000 * COIN;
    if(nHeight <= consensusParams.nLastBigReward)
        return 100 * COIN;

    int subsidyHalvingInterval = consensusParams.SubsidyHalvingInterval(nHeight);
    int subsidyHalvingWeight = consensusParams.SubsidyHalvingWeight(nHeight);
    int halvings = (subsidyHalvingWeight - 1) / subsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 1)
        return 0;

    int blocktimeDownscaleFactor = consensusParams.BlocktimeDownscaleFactor(nHeight);
    CAmount nSubsidy = 100 * COIN / blocktimeDownscaleFactor;
    // Subsidy is cut in half every 985500 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}

CoinsViews::CoinsViews(
    fs::path ldb_name,
    size_t cache_size_bytes,
    bool in_memory,
    bool should_wipe) : m_dbview(
                            gArgs.GetDataDirNet() / ldb_name, cache_size_bytes, in_memory, should_wipe),
                        m_catcherview(&m_dbview) {}

void CoinsViews::InitCache()
{
    AssertLockHeld(::cs_main);
    m_cacheview = std::make_unique<CCoinsViewCache>(&m_catcherview);
}

Chainstate::Chainstate(
    CTxMemPool* mempool,
    BlockManager& blockman,
    ChainstateManager& chainman,
    std::optional<uint256> from_snapshot_blockhash)
    : m_mempool(mempool),
      m_blockman(blockman),
      m_params(chainman.GetParams()),
      m_chainman(chainman),
      m_from_snapshot_blockhash(from_snapshot_blockhash) {}

void Chainstate::InitCoinsDB(
    size_t cache_size_bytes,
    bool in_memory,
    bool should_wipe,
    fs::path leveldb_name)
{
    if (m_from_snapshot_blockhash) {
        leveldb_name += "_" + m_from_snapshot_blockhash->ToString();
    }

    m_coins_views = std::make_unique<CoinsViews>(
        leveldb_name, cache_size_bytes, in_memory, should_wipe);
}

void Chainstate::InitCoinsCache(size_t cache_size_bytes)
{
    AssertLockHeld(::cs_main);
    assert(m_coins_views != nullptr);
    m_coinstip_cache_size_bytes = cache_size_bytes;
    m_coins_views->InitCache();
}

// Note that though this is marked const, we may end up modifying `m_cached_finished_ibd`, which
// is a performance-related implementation detail. This function must be marked
// `const` so that `CValidationInterface` clients (which are given a `const Chainstate*`)
// can call it.
//
bool Chainstate::IsInitialBlockDownload() const
{
    static bool fForceInitialBlocksDownloadMode = gArgs.GetBoolArg("-forceinitialblocksdownloadmode", DEFAULT_FORCE_INITIAL_BLOCKS_DOWNLOAD_MODE);
    if(fForceInitialBlocksDownloadMode)
        return true;

    // Optimization: pre-test latch before taking the lock.
    if (m_cached_finished_ibd.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (m_cached_finished_ibd.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (m_chain.Tip() == nullptr)
        return true;
    if (m_chain.Tip()->nChainWork < nMinimumChainWork)
        return true;
    if (m_chain.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    m_cached_finished_ibd.store(true, std::memory_order_relaxed);
    return false;
}

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
#if HAVE_SYSTEM
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    ReplaceAll(strCmd, "%s", safeStatus);

    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
#endif
}

void Chainstate::CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);

    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBlockDownload()) {
        return;
    }

    if (m_chainman.m_best_invalid && m_chainman.m_best_invalid->nChainWork > m_chain.Tip()->nChainWork + (GetBlockProof(*m_chain.Tip()) * 6)) {
        LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
        SetfLargeWorkInvalidChainFound(true);
    } else {
        SetfLargeWorkInvalidChainFound(false);
    }
}

// Called both upon regular invalid block discovery *and* InvalidateBlock
void Chainstate::InvalidChainFound(CBlockIndex* pindexNew)
{
    AssertLockHeld(cs_main);
    if (!m_chainman.m_best_invalid || pindexNew->nChainWork > m_chainman.m_best_invalid->nChainWork) {
        m_chainman.m_best_invalid = pindexNew;
    }
    if (m_chainman.m_best_header != nullptr && m_chainman.m_best_header->GetAncestor(pindexNew->nHeight) == pindexNew) {
        m_chainman.m_best_header = m_chain.Tip();
    }

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%f  date=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), FormatISO8601DateTime(pindexNew->GetBlockTime()));
    CBlockIndex *tip = m_chain.Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%f  date=%s\n", __func__,
      tip->GetBlockHash().ToString(), m_chain.Height(), log(tip->nChainWork.getdouble())/log(2.0),
      FormatISO8601DateTime(tip->GetBlockTime()));
    CheckForkWarningConditions();
}

// Same as InvalidChainFound, above, except not called directly from InvalidateBlock,
// which does its own setBlockIndexCandidates management.
void Chainstate::InvalidBlockFound(CBlockIndex* pindex, const BlockValidationState& state)
{
    AssertLockHeld(cs_main);
    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        m_chainman.m_failed_blocks.insert(pindex);
        m_blockman.m_dirty_blockindex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin) {
            txundo.vprevout.emplace_back();
            bool is_spent = inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
            assert(is_spent);
        }
    }
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

bool CScriptCheck::operator()() {
    if(checkOutput())
    {
        // Check the sender signature inside the output, used to identify VM sender
        CScript senderPubKey, senderSig;
        if(!ExtractSenderData(ptxTo->vout[nOut].scriptPubKey, &senderPubKey, &senderSig))
            return false;
        return VerifyScript(senderSig, senderPubKey, nullptr, nFlags, CachingTransactionSignatureOutputChecker(ptxTo, nOut, ptxTo->vout[nOut].nValue, cacheStore, *txdata), &error);
    }

    // Check the input signature
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;
    return VerifyScript(scriptSig, m_tx_out.scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *txdata), &error);
}

static CuckooCache::cache<uint256, SignatureCacheHasher> g_scriptExecutionCache;
static CSHA256 g_scriptExecutionCacheHasher;

bool InitScriptExecutionCache(size_t max_size_bytes)
{
    // Setup the salted hasher
    uint256 nonce = GetRandHash();
    // We want the nonce to be 64 bytes long to force the hasher to process
    // this chunk, which makes later hash computations more efficient. We
    // just write our 32-byte entropy twice to fill the 64 bytes.
    g_scriptExecutionCacheHasher.Write(nonce.begin(), 32);
    g_scriptExecutionCacheHasher.Write(nonce.begin(), 32);

    auto setup_results = g_scriptExecutionCache.setup_bytes(max_size_bytes);
    if (!setup_results) return false;

    const auto [num_elems, approx_size_bytes] = *setup_results;
    LogPrintf("Using %zu MiB out of %zu MiB requested for script execution cache, able to store %zu elements\n",
              approx_size_bytes >> 20, max_size_bytes >> 20, num_elems);
    return true;
}

/**
 * Check whether all of this transaction's input scripts succeed.
 *
 * This involves ECDSA signature checks so can be computationally intensive. This function should
 * only be called after the cheap sanity checks in CheckTxInputs passed.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Note that we may set state.reason to NOT_STANDARD for extra soft-fork flags in flags, block-checking
 * callers should probably reset it to CONSENSUS in such cases.
 *
 * Non-static (and re-declared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       std::vector<CScriptCheck>* pvChecks)
{
    if (tx.IsCoinBase()) return true;

    if (pvChecks) {
        pvChecks->reserve(tx.vin.size());
    }

    // First check if script executions have been cached with the same
    // flags. Note that this assumes that the inputs provided are
    // correct (ie that the transaction hash which is in tx's prevouts
    // properly commits to the scriptPubKey in the inputs view of that
    // transaction).
    uint256 hashCacheEntry;
    CSHA256 hasher = g_scriptExecutionCacheHasher;
    hasher.Write(tx.GetWitnessHash().begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
    AssertLockHeld(cs_main); //TODO: Remove this requirement by making CuckooCache not require external locks
    if (g_scriptExecutionCache.contains(hashCacheEntry, !cacheFullScriptStore)) {
        return true;
    }

    if (!txdata.m_spent_outputs_ready) {
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(tx.vin.size());

        for (const auto& txin : tx.vin) {
            const COutPoint& prevout = txin.prevout;
            const Coin& coin = inputs.AccessCoin(prevout);
            assert(!coin.IsSpent());
            spent_outputs.emplace_back(coin.out);
        }
        txdata.Init(tx, std::move(spent_outputs));
    }
    assert(txdata.m_spent_outputs.size() == tx.vin.size());

    for (unsigned int i = 0; i < tx.vin.size(); i++) {

        // We very carefully only pass in things to CScriptCheck which
        // are clearly committed to by tx' witness hash. This provides
        // a sanity check that our caching is not introducing consensus
        // failures through additional data in, eg, the coins being
        // spent being checked as a part of CScriptCheck.

        // Verify signature
        CScriptCheck check(txdata.m_spent_outputs[i], tx, i, flags, cacheSigStore, &txdata);
        if (pvChecks) {
            pvChecks->push_back(CScriptCheck());
            check.swap(pvChecks->back());
        } else if (!check()) {
            if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                // Check whether the failure was caused by a
                // non-mandatory script verification check, such as
                // non-standard DER encodings or non-null dummy
                // arguments; if so, ensure we return NOT_STANDARD
                // instead of CONSENSUS to avoid downstream users
                // splitting the network between upgraded and
                // non-upgraded nodes by banning CONSENSUS-failing
                // data providers.
                CScriptCheck check2(txdata.m_spent_outputs[i], tx, i,
                        flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheSigStore, &txdata);
                if (check2())
                    return state.Invalid(TxValidationResult::TX_NOT_STANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
            }
            // MANDATORY flag failures correspond to
            // TxValidationResult::TX_CONSENSUS. Because CONSENSUS
            // failures are the most serious case of validation
            // failures, we may need to consider using
            // RECENT_CONSENSUS_CHANGE for any script failure that
            // could be due to non-upgraded nodes which we may want to
            // support, to avoid splitting the network (but this
            // depends on the details of how net_processing handles
            // such errors).
            return state.Invalid(TxValidationResult::TX_CONSENSUS, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
        }
    }

    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        // Verify sender output signature
        if(tx.vout[i].scriptPubKey.HasOpSender())
        {
            CScriptCheck check(tx, i, 0, cacheSigStore, &txdata);
            if (pvChecks) {
                pvChecks->push_back(CScriptCheck());
                check.swap(pvChecks->back());
            } else if (!check()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, strprintf("sender-output-script-verify-failed (%s)", ScriptErrorString(check.GetScriptError())));
            }
        }
    }

    if (cacheFullScriptStore && !pvChecks) {
        // We executed all of the provided scripts, and were told to
        // cache the result. Do so now.
        g_scriptExecutionCache.insert(hashCacheEntry);
    }

    return true;
}

bool AbortNode(BlockValidationState& state, const std::string& strMessage, const bilingual_str& userMessage)
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // If the coin already exists as an unspent coin in the cache, then the
    // possible_overwrite parameter to AddCoin must be set to true. We have
    // already checked whether an unspent coin exists above using HaveCoin, so
    // we don't need to guess. When fClean is false, an unspent coin already
    // existed and it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult Chainstate::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view, bool* pfClean)
{
    AssertLockHeld(::cs_main);
    if (pfClean)
        *pfClean = false;
    bool fClean = true;

    CBlockUndo blockUndo;
    if (!UndoReadFromDisk(blockUndo, pindex)) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    /////////////////////////////////////////////////////////// // runebase
    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;
    ///////////////////////////////////////////////////////////

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();
        bool is_coinbase = tx.IsCoinBase();
        bool is_coinstake = tx.IsCoinStake();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                bool is_spent = view.SpendCoin(out, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase || is_coinstake != coin.fCoinStake) {
                    fClean = false; // transaction output mismatch
                }
            }
        }

        /////////////////////////////////////////////////////////// // runebase
        if (pfClean == NULL && fAddressIndex) {

            for (unsigned int k = tx.vout.size(); k-- > 0;) {
                const CTxOut &out = tx.vout[k];

                CTxDestination dest;
                if (ExtractDestination({hash, k}, out.scriptPubKey, dest)) {
                    valtype bytesID(std::visit(DataVisitor(), dest));
                    if(bytesID.empty()) {
                        continue;
                    }
                    valtype addressBytes(32);
                    std::copy(bytesID.begin(), bytesID.end(), addressBytes.begin());
                    // undo receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(dest.index(), uint256(addressBytes), pindex->nHeight, i, hash, k, false), out.nValue));
                    // undo unspent index
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(dest.index(), uint256(addressBytes), hash, k), CAddressUnspentValue()));
                }
            }
        }
        ///////////////////////////////////////////////////////////

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }
            for (unsigned int j = tx.vin.size(); j > 0;) {
                --j;
                const COutPoint& out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;

                if (pfClean == NULL && fAddressIndex) {
                    const auto &undo = txundo.vprevout[j];
                    const bool isTxCoinStake = tx.IsCoinStake();
                    const CTxIn input = tx.vin[j];
                    const CTxOut &prevout = view.GetOutputFor(input);

                    CTxDestination dest;
                    if (ExtractDestination(input.prevout, prevout.scriptPubKey, dest)) {
                        valtype bytesID(std::visit(DataVisitor(), dest));
                        if(bytesID.empty()) {
                            continue;
                        }
                        valtype addressBytes(32);
                        std::copy(bytesID.begin(), bytesID.end(), addressBytes.begin());
                        // undo spending activity
                        addressIndex.push_back(std::make_pair(CAddressIndexKey(dest.index(), uint256(addressBytes), pindex->nHeight, i, hash, j, true), prevout.nValue * -1));
                        // restore unspent index
                        addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(dest.index(), uint256(addressBytes), input.prevout.hash, input.prevout.n), CAddressUnspentValue(prevout.nValue, prevout.scriptPubKey, undo.nHeight, isTxCoinStake)));
                    }
                }
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    globalState->setRoot(uintToh256(pindex->pprev->hashStateRoot)); // runebase
    globalState->setRootUTXO(uintToh256(pindex->pprev->hashUTXORoot)); // runebase

    if(pfClean == NULL && fLogEvents){
        pstorageresult->deleteResults(block.vtx);
        m_blockman.m_block_tree_db->EraseHeightIndex(pindex->nHeight);
    }

    // The stake and delegate index is needed for MPoS, update it while MPoS is active
    const CChainParams& chainparams = Params();
    if(pindex->nHeight <= chainparams.GetConsensus().nLastMPoSBlock)
    {
        m_blockman.m_block_tree_db->EraseStakeIndex(pindex->nHeight);
        if(pindex->IsProofOfStake() && pindex->HasProofOfDelegation())
            m_blockman.m_block_tree_db->EraseDelegateIndex(pindex->nHeight);
    }

    //////////////////////////////////////////////////// // runebase
    if (pfClean == NULL && fAddressIndex) {
        if (!m_blockman.m_block_tree_db->EraseAddressIndex(addressIndex)) {
            error("Failed to delete address index");
            return DISCONNECT_FAILED;
        }
        if (!m_blockman.m_block_tree_db->UpdateAddressUnspentIndex(addressUnspentIndex)) {
            error("Failed to write address unspent index");
            return DISCONNECT_FAILED;
        }
    }
    ////////////////////////////////////////////////////

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void StartScriptCheckWorkerThreads(int threads_num)
{
    scriptcheckqueue.StartWorkerThreads(threads_num);
}

void StopScriptCheckWorkerThreads()
{
    scriptcheckqueue.StopWorkerThreads();
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    const ChainstateManager& m_chainman;
    int m_bit;

public:
    explicit WarningBitsConditionChecker(const ChainstateManager& chainman, int bit) : m_chainman{chainman}, m_bit(bit) {}

    int64_t BeginTime(const Consensus::Params& params) const override { return 0; }
    int64_t EndTime(const Consensus::Params& params) const override { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return pindex->nHeight >= params.MinBIP9WarningHeight &&
               ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> m_bit) & 1) != 0 &&
               ((m_chainman.m_versionbitscache.ComputeBlockVersion(pindex->pprev, params) >> m_bit) & 1) == 0;
    }
};

static std::array<ThresholdConditionCache, VERSIONBITS_NUM_BITS> warningcache GUARDED_BY(cs_main);

static unsigned int GetBlockScriptFlags(const CBlockIndex& block_index, const ChainstateManager& chainman)
{
    const Consensus::Params& consensusparams = chainman.GetConsensus();

    // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
    // retroactively applied to testnet)
    // However, only one historical block violated the P2SH rules (on both
    // mainnet and testnet).
    // Similarly, only one historical block violated the TAPROOT rules on
    // mainnet.
    // For simplicity, always leave P2SH+WITNESS+TAPROOT on except for the two
    // violating blocks.
    uint32_t flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
    const auto it{consensusparams.script_flag_exceptions.find(*Assert(block_index.phashBlock))};
    if (it != consensusparams.script_flag_exceptions.end()) {
        flags = it->second;
    }

    // Enforce the DERSIG (BIP66) rule
    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_DERSIG)) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Enforce CHECKLOCKTIMEVERIFY (BIP65)
    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_CLTV)) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Enforce CHECKSEQUENCEVERIFY (BIP112)
    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_CSV)) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Enforce BIP147 NULLDUMMY (activated simultaneously with segwit)
    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_SEGWIT)) {
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    // Start support sender address in contract output
    if (block_index.nHeight >= consensusparams.QIP5Height) {
        flags |= SCRIPT_OUTPUT_SENDER;
    }

    return flags;
}

unsigned int GetContractScriptFlags(int nHeight, const Consensus::Params& consensusparams) {
    unsigned int flags = SCRIPT_EXEC_BYTE_CODE;

    // Start support sender address in contract output
    if (nHeight >= consensusparams.QIP5Height) {
        flags |= SCRIPT_OUTPUT_SENDER;
    }

    return flags;
}


static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeUndo = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeTotal = 0;
static int64_t nBlocksTotal = 0;

/////////////////////////////////////////////////////////////////////// runebase
bool GetSpentCoinFromBlock(const CBlockIndex* pindex, COutPoint prevout, Coin* coin) {
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
        return error("GetSpentCoinFromBlock(): Could not read block from disk");
    }

    for(size_t j = 1; j < block.vtx.size(); ++j) {
        CTransactionRef& tx = block.vtx[j];
        for(size_t k = 0; k < tx->vin.size(); ++k) {
            const COutPoint& tmpprevout = tx->vin[k].prevout;
            if(tmpprevout == prevout) {
                CBlockUndo undo;
                if(!UndoReadFromDisk(undo, pindex)) {
                    return error("GetSpentCoinFromBlock(): Could not read undo block from disk");
                }

                if(undo.vtxundo.size() != block.vtx.size() - 1) {
                    return error("GetSpentCoinFromBlock(): undo tx size not equal to block tx size");
                }

                CTxUndo &txundo = undo.vtxundo[j-1]; // no vtxundo for coinbase

                if(txundo.vprevout.size() != tx->vin.size()) {
                    return error("GetSpentCoinFromBlock(): undo tx vin size not equal to block tx vin size");
                }

                *coin = txundo.vprevout[k];
                return true;
            }

        }
    }
    return false;
}

bool GetSpentCoinFromMainChain(const CBlockIndex* pforkPrev, COutPoint prevoutStake, Coin* coin, CChain& chain) {
    const CBlockIndex* pforkBase = chain.FindFork(pforkPrev);

    // If the forkbase is more than coinbaseMaturity blocks in the past, do not attempt to scan the main chain.
    int nHeight = chain.Tip()->nHeight;
    int coinbaseMaturity = Params().GetConsensus().CoinbaseMaturity(nHeight);
    if(nHeight - pforkBase->nHeight > coinbaseMaturity) {
        return error("The fork's base is behind by more than 500 blocks");
    }

    // First, we make sure that the prevout has not been spent in any of pforktip's ancestors as the prevoutStake.
    // This is done to prevent a single staker building a long chain based on only a single prevout.
    {
        const CBlockIndex* pindex = pforkPrev;
        while(pindex && pindex != pforkBase) {
            // The coinstake has already been spent in the fork.
            if(pindex->prevoutStake == prevoutStake) {
                return error("prevout already spent in the orphan chain");
            }
            pindex = pindex->pprev;
        }
    }

    // Scan through blocks until we reach the forkbase to check if the prevoutStake has been spent in one of those blocks
    // If it not in any of those blocks, and not in the utxo set, it can't be spendable in the orphan chain.
    {
        CBlockIndex* pindex = chain.Tip();
        while(pindex && pindex != pforkBase) {
            if(GetSpentCoinFromBlock(pindex, prevoutStake, coin)) {
                return true;
            }
            pindex = pindex->pprev;
        }
    }

    return false;
}

bool CheckOpSender(const CTransaction& tx, const CChainParams& chainparams, int nHeight){
    if(!tx.HasOpSender())
        return true;

    if(!(nHeight >= chainparams.GetConsensus().QIP5Height))
        return false;

    // Check that the sender address inside the output is only valid for contract outputs
    for (const CTxOut& txout : tx.vout)
    {
        bool hashOpSender = txout.scriptPubKey.HasOpSender();
        if(hashOpSender &&
                !(txout.scriptPubKey.HasOpCreate() ||
                  txout.scriptPubKey.HasOpCall()))
        {
            return false;
        }

        // Solve the script that match the sender templates
        if(hashOpSender && !ExtractSenderData(txout.scriptPubKey, nullptr, nullptr))
            return false;
    }

    return true;
}

bool CheckSenderScript(const CCoinsViewCache& view, const CTransaction& tx){
    // Check for the sender that pays the coins
    CScript script = view.AccessCoin(tx.vin[0].prevout).out.scriptPubKey;
    if(!script.IsPayToPubkeyHash() && !script.IsPayToPubkey()){
        return false;
    }

    // Check for additional VM sender
    if(!tx.HasOpSender())
        return true;

    // Check for the VM sender that is encoded into the output
    for (const CTxOut& txout : tx.vout)
    {
        if(txout.scriptPubKey.HasOpSender())
        {
            // Extract the sender data
            CScript senderPubKey, senderSig;
            if(!ExtractSenderData(txout.scriptPubKey, &senderPubKey, &senderSig))
                return false;

            // Check that the pub key is valid sender that can be used in the VM
            if(!senderPubKey.IsPayToPubkeyHash() && !senderPubKey.IsPayToPubkey())
                return false;

            // Get the signature stack
            std::vector <std::vector<unsigned char> > stack;
            if (!EvalScript(stack, senderSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;

            // Check that the signature script contains only signature and public key (2 items)
            if(stack.size() != STANDARD_SENDER_STACK_ITEMS)
                return false;

            // Check that the items size is no more than 80 bytes
            for(size_t i=0; i < stack.size(); i++)
            {
                if(stack[i].size() > MAX_STANDARD_SENDER_STACK_ITEM_SIZE)
                    return false;
            }
        }
    }

    return true;
}

std::vector<ResultExecute> CallContract(const dev::Address& addrContract, std::vector<unsigned char> opcode, Chainstate& chainstate, const dev::Address& sender, uint64_t gasLimit, CAmount nAmount){
    CBlock block;
    CMutableTransaction tx;

    CBlockIndex* pblockindex = &(chainstate.m_blockman.m_block_index[chainstate.m_chain.Tip()->GetBlockHash()]);
    ReadBlockFromDisk(block, pblockindex, Params().GetConsensus());
    block.nTime = GetAdjustedTimeSeconds();

    if(block.IsProofOfStake())
    	block.vtx.erase(block.vtx.begin()+2,block.vtx.end());
    else
    	block.vtx.erase(block.vtx.begin()+1,block.vtx.end());

    RunebaseDGP runebaseDGP(globalState.get(), chainstate, fGettingValuesDGP);
    uint64_t blockGasLimit = runebaseDGP.getBlockGasLimit(chainstate.m_chain.Tip()->nHeight + 1);

    if(gasLimit == 0){
        gasLimit = blockGasLimit - 1;
    }
    dev::Address senderAddress = sender == dev::Address() ? dev::Address("ffffffffffffffffffffffffffffffffffffffff") : sender;
    tx.vout.push_back(CTxOut(nAmount, CScript() << OP_DUP << OP_HASH160 << senderAddress.asBytes() << OP_EQUALVERIFY << OP_CHECKSIG));
    block.vtx.push_back(MakeTransactionRef(CTransaction(tx)));
    dev::u256 nonce = globalState->getNonce(senderAddress);
 
    RunebaseTransaction callTransaction;
    if(addrContract == dev::Address())
    {
        callTransaction = RunebaseTransaction(nAmount, 1, dev::u256(gasLimit), opcode, nonce);
    }
    else
    {
        callTransaction = RunebaseTransaction(nAmount, 1, dev::u256(gasLimit), addrContract, opcode, nonce);
    }
    callTransaction.forceSender(senderAddress);
    callTransaction.setVersion(VersionVM::GetEVMDefault());

    
    ByteCodeExec exec(block, std::vector<RunebaseTransaction>(1, callTransaction), blockGasLimit, pblockindex, chainstate.m_chain);
    exec.performByteCode(dev::eth::Permanence::Reverted);
    return exec.getResult();
}

bool CheckMinGasPrice(std::vector<EthTransactionParams>& etps, const uint64_t& minGasPrice){
    for(EthTransactionParams& etp : etps){
        if(etp.gasPrice < dev::u256(minGasPrice))
            return false;
    }
    return true;
}

bool CheckReward(const CBlock& block, BlockValidationState& state, int nHeight, const Consensus::Params& consensusParams, CAmount nFees, CAmount gasRefunds, CAmount nActualStakeReward, const std::vector<CTxOut>& vouts, CAmount nValueCoinPrev, bool delegateOutputExist, CChain& chain, node::BlockManager& blockman)
{
    size_t offset = block.IsProofOfStake() ? 1 : 0;
    std::vector<CTxOut> vTempVouts=block.vtx[offset]->vout;
    std::vector<CTxOut>::iterator it;
    for(size_t i = 0; i < vouts.size(); i++){
        it=std::find(vTempVouts.begin(), vTempVouts.end(), vouts[i]);
        if(it==vTempVouts.end()){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-gas-refund-missing", "CheckReward(): Gas refund missing");
        }else{
            vTempVouts.erase(it);
        }
    }

    // Check block reward
    if (block.IsProofOfWork())
    {
        // Check proof-of-work reward
        CAmount blockReward = nFees + GetBlockSubsidy(nHeight, consensusParams);
        if (block.vtx[offset]->GetValueOut() > blockReward) {
            LogPrintf("ERROR: ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)\n", block.vtx[offset]->GetValueOut(), blockReward);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-amount");
        }
    }
    else
    {
        // Check full reward
        CAmount blockReward = nFees + GetBlockSubsidy(nHeight, consensusParams);
        if (nActualStakeReward > blockReward)
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-amount", strprintf("CheckReward(): coinstake pays too much (actual=%d vs limit=%d)", nActualStakeReward, blockReward));

        // The first proof-of-stake blocks get full reward, the rest of them are split between recipients
        int rewardRecipients = 1;
        int nPrevHeight = nHeight -1;
        if(nPrevHeight >= consensusParams.nFirstMPoSBlock && nPrevHeight < consensusParams.nLastMPoSBlock)
            rewardRecipients = consensusParams.nMPoSRewardRecipients;

        // Check reward recipients number
        if(rewardRecipients < 1)
            return error("CheckReward(): invalid reward recipients");

        // Check reward can cover the gas refunds
        if(blockReward < gasRefunds){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-gas-greater-than-reward", "CheckReward(): Block Reward is less than total gas refunds");
        }

        CAmount splitReward = (blockReward - gasRefunds) / rewardRecipients;

        // Check that the reward is in the second output for the staker and the third output for the delegate
        // Delegation contract data like the fee is checked in CheckProofOfStake
        if(block.HasProofOfDelegation())
        {
            CAmount nReward = blockReward - gasRefunds - splitReward * (rewardRecipients -1);
            CAmount nValueStaker = block.vtx[offset]->vout[1].nValue;
            CAmount nValueDelegate = delegateOutputExist ? block.vtx[offset]->vout[2].nValue : 0;
            CAmount nMinedReward = nValueStaker + nValueDelegate - nValueCoinPrev;
            if(nReward != nMinedReward)
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-delegate-reward", "CheckReward(): The block reward is not split correctly between the staker and the delegate");
        }

        //if only 1 then no MPoS logic required
        if(rewardRecipients == 1){
            return true;
        }

        // Generate the list of mpos outputs including all of their parameters
        std::vector<CTxOut> mposOutputList;
        if(!GetMPoSOutputs(mposOutputList, splitReward, nPrevHeight, consensusParams, chain, blockman))
            return error("CheckReward(): cannot create the list of MPoS outputs");
      
        for(size_t i = 0; i < mposOutputList.size(); i++){
            it=std::find(vTempVouts.begin(), vTempVouts.end(), mposOutputList[i]);
            if(it==vTempVouts.end()){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-mpos-missing", "CheckReward(): An MPoS participant was not properly paid");
            }else{
                vTempVouts.erase(it);
            }
        }

        vTempVouts.clear();
    }

    return true;
}

valtype GetSenderAddress(const CTransaction& tx, const CCoinsViewCache* coinsView, const std::vector<CTransactionRef>* blockTxs, Chainstate& chainstate, const CTxMemPool* mempool, int nOut = -1){
    CScript script;
    bool scriptFilled=false; //can't use script.empty() because an empty script is technically valid

    // Try get the sender script from the output script
    if(nOut > -1)
        scriptFilled = ExtractSenderData(tx.vout[nOut].scriptPubKey, &script, nullptr);

    // Check if the transaction has inputs
    if(tx.vin.size() == 0) {
        return valtype();
    }

    // Check the current (or in-progress) block for zero-confirmation change spending that won't yet be in txindex
    if(!scriptFilled && blockTxs){
        for(auto btx : *blockTxs){
            if(btx->GetHash() == tx.vin[0].prevout.hash){
                script = btx->vout[tx.vin[0].prevout.n].scriptPubKey;
                scriptFilled=true;
                break;
            }
        }
    }
    if(!scriptFilled && coinsView){
        script = coinsView->AccessCoin(tx.vin[0].prevout).out.scriptPubKey;
        scriptFilled = true;
    }
    if(!scriptFilled)
    {
        CTransactionRef txPrevout;
        uint256 hashBlock;
        txPrevout = node::GetTransaction(nullptr, mempool, tx.vin[0].prevout.hash, Params().GetConsensus(), hashBlock, &chainstate);
        if(txPrevout != nullptr){
            script = txPrevout->vout[tx.vin[0].prevout.n].scriptPubKey;
        } else {
            LogPrintf("Error fetching transaction details of tx %s. This will probably cause more errors", tx.vin[0].prevout.hash.ToString());
            return valtype();
        }
    }

	CTxDestination addressBit;
    TxoutType txType=TxoutType::NONSTANDARD;
	if(ExtractDestination(script, addressBit, &txType)){
		if ((txType == TxoutType::PUBKEY || txType == TxoutType::PUBKEYHASH) &&
                std::holds_alternative<PKHash>(addressBit)){
			PKHash senderAddress(std::get<PKHash>(addressBit));
			return valtype(senderAddress.begin(), senderAddress.end());
		}
	}
    //prevout is not a standard transaction format, so just return 0
    return valtype();
}

UniValue vmLogToJSON(const ResultExecute& execRes, const CTransaction& tx, const CBlock& block, CChain& chain){
    UniValue result(UniValue::VOBJ);
    if(tx != CTransaction())
        result.pushKV("txid", tx.GetHash().GetHex());
    result.pushKV("address", execRes.execRes.newAddress.hex());
    if(block.GetHash() != CBlock().GetHash()){
        result.pushKV("time", block.GetBlockTime());
        result.pushKV("blockhash", block.GetHash().GetHex());
        result.pushKV("blockheight", chain.Tip()->nHeight + 1);
    } else {
        result.pushKV("time", GetAdjustedTimeSeconds());
        result.pushKV("blockheight", chain.Tip()->nHeight);
    }
    UniValue logEntries(UniValue::VARR);
    dev::eth::LogEntries logs = execRes.txRec.log();
    for(dev::eth::LogEntry log : logs){
        UniValue logEntrie(UniValue::VOBJ);
        logEntrie.pushKV("address", log.address.hex());
        UniValue topics(UniValue::VARR);
        for(dev::h256 l : log.topics){
            UniValue topicPair(UniValue::VOBJ);
            topicPair.pushKV("raw", l.hex());
            topics.push_back(topicPair);
            //TODO add "pretty" field for human readable data
        }
        UniValue dataPair(UniValue::VOBJ);
        dataPair.pushKV("raw", HexStr(log.data));
        logEntrie.pushKV("data", dataPair);
        logEntrie.pushKV("topics", topics);
        logEntries.push_back(logEntrie);
    }
    result.pushKV("entries", logEntries);
    return result;
}

void writeVMlog(const std::vector<ResultExecute>& res, CChain& chain, const CTransaction& tx, const CBlock& block){
    fs::path runebaseDir = gArgs.GetDataDirNet() / "vmExecLogs.json";
    std::stringstream ss;
    if(fIsVMlogFile){
        ss << ",";
    } else {
        std::ofstream file(PathToString(runebaseDir), std::ios::out | std::ios::app);
        file << "{\"logs\":[]}";
        file.close();
    }

    for(size_t i = 0; i < res.size(); i++){
        ss << vmLogToJSON(res[i], tx, block, chain).write();
        if(i != res.size() - 1){
            ss << ",";
        } else {
            ss << "]}";
        }
    }
    
    std::ofstream file(PathToString(runebaseDir), std::ios::in | std::ios::out);
    file.seekp(-2, std::ios::end);
    file << ss.str();
    file.close();
    fIsVMlogFile = true;
}

LastHashes::LastHashes()
{}

void LastHashes::set(const CBlockIndex *tip)
{
    clear();

    m_lastHashes.resize(256);
    for(int i=0;i<256;i++){
        if(!tip)
            break;
        m_lastHashes[i]= uintToh256(*tip->phashBlock);
        tip = tip->pprev;
    }
}

dev::h256s LastHashes::precedingHashes(const dev::h256 &) const
{
    return m_lastHashes;
}

void LastHashes::clear()
{
    m_lastHashes.clear();
}

bool ByteCodeExec::performByteCode(dev::eth::Permanence type){
    for(RunebaseTransaction& tx : txs){
        //validate VM version
        if(tx.getVersion().toRaw() != VersionVM::GetEVMDefault().toRaw()){
            return false;
        }
        dev::eth::EnvInfo envInfo(BuildEVMEnvironment());
        if(!tx.isCreation() && !globalState->addressInUse(tx.receiveAddress())){
            dev::eth::ExecutionResult execRes;
            execRes.excepted = dev::eth::TransactionException::Unknown;
            result.push_back(ResultExecute{execRes, RunebaseTransactionReceipt(dev::h256(), dev::h256(), dev::u256(), dev::eth::LogEntries()), CTransaction()});
            continue;
        }
        result.push_back(globalState->execute(envInfo, *globalSealEngine.get(), tx, chain, type, OnOpFunc()));
    }
    globalState->db().commit();
    globalState->dbUtxo().commit();
    globalSealEngine.get()->deleteAddresses.clear();
    return true;
}

bool ByteCodeExec::processingResults(ByteCodeExecResult& resultBCE){
	const Consensus::Params& consensusParams = Params().GetConsensus();
    for(size_t i = 0; i < result.size(); i++){
        uint64_t gasUsed = (uint64_t) result[i].execRes.gasUsed;

        if(result[i].execRes.excepted != dev::eth::TransactionException::None){
        	// refund coins sent to the contract to the sender
        	if(txs[i].value() > 0){
        		CMutableTransaction tx;
        		tx.vin.push_back(CTxIn(h256Touint(txs[i].getHashWith()), txs[i].getNVout(), CScript() << OP_SPEND));
        		CScript script(CScript() << OP_DUP << OP_HASH160 << txs[i].sender().asBytes() << OP_EQUALVERIFY << OP_CHECKSIG);
        		tx.vout.push_back(CTxOut(CAmount(txs[i].value()), script));
        		resultBCE.valueTransfers.push_back(CTransaction(tx));
        	}
        	if(!(chain.Height() >= consensusParams.QIP7Height && result[i].execRes.excepted == dev::eth::TransactionException::RevertInstruction)){
        	resultBCE.usedGas += gasUsed;
        	}
        }

        if(result[i].execRes.excepted == dev::eth::TransactionException::None || (chain.Height() >= consensusParams.QIP7Height && result[i].execRes.excepted == dev::eth::TransactionException::RevertInstruction)){
        	if(txs[i].gas() > UINT64_MAX ||
        			result[i].execRes.gasUsed > UINT64_MAX ||
					txs[i].gasPrice() > UINT64_MAX){
        		return false;
        	}
        	uint64_t gas = (uint64_t) txs[i].gas();
        	uint64_t gasPrice = (uint64_t) txs[i].gasPrice();

        	resultBCE.usedGas += gasUsed;
        	int64_t amount = (gas - gasUsed) * gasPrice;
        	if(amount < 0){
        		return false;
        	}
        	if(amount > 0){
        		// Refund the rest of the amount to the sender that provide the coins for the contract
				CScript script(CScript() << OP_DUP << OP_HASH160 << txs[i].getRefundSender().asBytes() << OP_EQUALVERIFY << OP_CHECKSIG);
				resultBCE.refundOutputs.push_back(CTxOut(amount, script));
				resultBCE.refundSender += amount;
        	}
        }

        if(result[i].tx != CTransaction()){
            resultBCE.valueTransfers.push_back(result[i].tx);
        }
    }
    return true;
}

dev::eth::EnvInfo ByteCodeExec::BuildEVMEnvironment(){
    CBlockIndex* tip = pindex;
    dev::eth::BlockHeader header;
    header.setNumber(tip->nHeight + 1);
    header.setTimestamp(block.nTime);
    header.setDifficulty(dev::u256(block.nBits));
    header.setGasLimit(blockGasLimit);

    lastHashes.set(tip);

    if(block.IsProofOfStake()){
        header.setAuthor(EthAddrFromScript(block.vtx[1]->vout[1].scriptPubKey));
    }else {
        header.setAuthor(EthAddrFromScript(block.vtx[0]->vout[0].scriptPubKey));
    }
    dev::u256 gasUsed;
    int &chainID = const_cast<int&>(globalSealEngine->chainParams().chainID);
    chainID = runebaseutils::eth_getChainId(tip->nHeight);
    dev::eth::EnvInfo env(header, lastHashes, gasUsed, chainID);
    return env;
}

dev::Address ByteCodeExec::EthAddrFromScript(const CScript& script){
    CTxDestination addressBit;
    TxoutType txType=TxoutType::NONSTANDARD;
    if(ExtractDestination(script, addressBit, &txType)){
        if ((txType == TxoutType::PUBKEY || txType == TxoutType::PUBKEYHASH) &&
            std::holds_alternative<PKHash>(addressBit)){
            PKHash addressKey(std::get<PKHash>(addressBit));
            std::vector<unsigned char> addr(addressKey.begin(), addressKey.end());
            return dev::Address(addr);
        }
    }
    //if not standard or not a pubkey or pubkeyhash output, then return 0
    return dev::Address();
}

bool RunebaseTxConverter::extractionRunebaseTransactions(ExtractRunebaseTX& runebasetx){
    // Get the address of the sender that pay the coins for the contract transactions
    refundSender = dev::Address(GetSenderAddress(txBit, view, blockTransactions, chainstate, mempool));

    // Extract contract transactions
    std::vector<RunebaseTransaction> resultTX;
    std::vector<EthTransactionParams> resultETP;
    for(size_t i = 0; i < txBit.vout.size(); i++){
        if(txBit.vout[i].scriptPubKey.HasOpCreate() || txBit.vout[i].scriptPubKey.HasOpCall()){
            if(receiveStack(txBit.vout[i].scriptPubKey)){
                EthTransactionParams params;
                if(parseEthTXParams(params)){
                    resultTX.push_back(createEthTX(params, i));
                    resultETP.push_back(params);
                }else{
                    return false;
                }
            }else{
                return false;
            }
        }
    }
    runebasetx = std::make_pair(resultTX, resultETP);
    return true;
}

bool RunebaseTxConverter::receiveStack(const CScript& scriptPubKey){
    sender = false;
    EvalScript(stack, scriptPubKey, nFlags, BaseSignatureChecker(), SigVersion::BASE, nullptr);
    if (stack.empty())
        return false;

    CScript scriptRest(stack.back().begin(), stack.back().end());
    stack.pop_back();
    sender = scriptPubKey.HasOpSender();

    opcode = (opcodetype)(*scriptRest.begin());
    if((opcode == OP_CREATE && stack.size() < correctedStackSize(4)) || (opcode == OP_CALL && stack.size() < correctedStackSize(5))){
        stack.clear();
        sender = false;
        return false;
    }

    return true;
}

bool RunebaseTxConverter::parseEthTXParams(EthTransactionParams& params){
    try{
        dev::Address receiveAddress;
        valtype vecAddr;
        if (opcode == OP_CALL)
        {
            vecAddr = stack.back();
            stack.pop_back();
            receiveAddress = dev::Address(vecAddr);
        }
        if(stack.size() < correctedStackSize(4))
            return false;

        if(stack.back().size() < 1){
            return false;
        }
        valtype code(stack.back());
        stack.pop_back();
        uint64_t gasPrice = CScriptNum::vch_to_uint64(stack.back());
        stack.pop_back();
        uint64_t gasLimit = CScriptNum::vch_to_uint64(stack.back());
        stack.pop_back();
        if(gasPrice > INT64_MAX || gasLimit > INT64_MAX){
            return false;
        }
        //we track this as CAmount in some places, which is an int64_t, so constrain to INT64_MAX
        if(gasPrice !=0 && gasLimit > INT64_MAX / gasPrice){
            //overflows past 64bits, reject this tx
            return false;
        }
        if(stack.back().size() > 4){
            return false;
        }
        VersionVM version = VersionVM::fromRaw((uint32_t)CScriptNum::vch_to_uint64(stack.back()));
        stack.pop_back();
        params.version = version;
        params.gasPrice = dev::u256(gasPrice);
        params.receiveAddress = receiveAddress;
        params.code = code;
        params.gasLimit = dev::u256(gasLimit);
        return true;
    }
    catch(const scriptnum_error& err){
        LogPrintf("Incorrect parameters to VM.");
        return false;
    }
}

RunebaseTransaction RunebaseTxConverter::createEthTX(const EthTransactionParams& etp, uint32_t nOut){
    RunebaseTransaction txEth;
    if (etp.receiveAddress == dev::Address() && opcode != OP_CALL){
        txEth = RunebaseTransaction(txBit.vout[nOut].nValue, etp.gasPrice, etp.gasLimit, etp.code, dev::u256(0));
    }
    else{
        txEth = RunebaseTransaction(txBit.vout[nOut].nValue, etp.gasPrice, etp.gasLimit, etp.receiveAddress, etp.code, dev::u256(0));
    }
    dev::Address sender(GetSenderAddress(txBit, view, blockTransactions, chainstate, mempool, (int)nOut));
    txEth.forceSender(sender);
    txEth.setHashWith(uintToh256(txBit.GetHash()));
    txEth.setNVout(nOut);
    txEth.setVersion(etp.version);
    txEth.setRefundSender(refundSender);

    return txEth;
}

size_t RunebaseTxConverter::correctedStackSize(size_t size){
    // OP_SENDER add 3 more parameters in stack besides those for OP_CREATE or OP_CALL
    return sender ? size + 3 : size;
}
///////////////////////////////////////////////////////////////////////

bool CheckDelegationOutput(const CBlock& block, bool& delegateOutputExist, CCoinsViewCache& view, Chainstate& chainstate)
{
    if(block.IsProofOfStake() && block.HasProofOfDelegation())
    {
        uint160 staker;
        std::vector<unsigned char> vchPubKey;
        if(GetBlockPublicKey(block, vchPubKey))
        {
            staker = uint160(ToByteVector(CPubKey(vchPubKey).GetID()));
            uint160 address;
            uint8_t fee = 0;
            if(GetBlockDelegation(block, staker, address, fee, view, chainstate))
            {
                delegateOutputExist = IsDelegateOutputExist(fee);
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }

    return true;
}

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool Chainstate::ConnectBlock(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex,
                               CCoinsViewCache& view, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    assert(pindex);

    uint256 block_hash{block.GetHash()};
    assert(*pindex->phashBlock == block_hash);

    int64_t nTimeStart = GetTimeMicros();

    ///////////////////////////////////////////////// // runebase
    RunebaseDGP runebaseDGP(globalState.get(), *this, fGettingValuesDGP);
    globalSealEngine->setRunebaseSchedule(runebaseDGP.getGasSchedule(pindex->nHeight + (pindex->nHeight+1 >= m_params.GetConsensus().QIP7Height ? 0 : 1) ));
    uint32_t sizeBlockDGP = runebaseDGP.getBlockSize(pindex->nHeight + (pindex->nHeight+1 >= m_params.GetConsensus().QIP7Height ? 0 : 1));
    uint64_t minGasPrice = runebaseDGP.getMinGasPrice(pindex->nHeight + (pindex->nHeight+1 >= m_params.GetConsensus().QIP7Height ? 0 : 1));
    uint64_t blockGasLimit = runebaseDGP.getBlockGasLimit(pindex->nHeight + (pindex->nHeight+1 >= m_params.GetConsensus().QIP7Height ? 0 : 1));
    dgpMaxBlockSize = sizeBlockDGP ? sizeBlockDGP : dgpMaxBlockSize;
    updateBlockSizeParams(dgpMaxBlockSize);
    CBlock checkBlock(block.GetBlockHeader());
    std::vector<CTxOut> checkVouts;

    /////////////////////////////////////////////////
    // We recheck the hardened checkpoints here since ContextualCheckBlock(Header) is not called in ConnectBlock.
    if(fCheckpointsEnabled && !m_blockman.CheckHardened(pindex->nHeight, block.GetHash(), m_params.Checkpoints())) {
        return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT, "bad-fork-hardened-checkpoint", strprintf("%s: expected hardened checkpoint at height %d", __func__, pindex->nHeight));
    }


    // Move this check from CheckBlock to ConnectBlock as it depends on DGP values
    if (block.vtx.empty() || block.vtx.size() > dgpMaxBlockSize || ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) > dgpMaxBlockSize) // runebase
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");

    // Move this check from ContextualCheckBlock to ConnectBlock as it depends on DGP values
    if (GetBlockWeight(block) > dgpMaxBlockWeight) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", strprintf("%s : weight limit failed", __func__));
    }

    bool delegateOutputExist = false;
    if (!CheckDelegationOutput(block, delegateOutputExist, view, *this)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-delegate-output", strprintf("%s : delegation output check failed", __func__));
    }

    if (block.IsProofOfStake() && pindex->nHeight > m_params.GetConsensus().nEnableHeaderSignatureHeight && !CheckBlockInputPubKeyMatchesOutputPubKey(block, view, delegateOutputExist)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-coinstake-input-output-mismatch");
    }

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see NeedsRedownload()
    // for one approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // m_adjusted_time_callback() to go backward).
    if (!CheckBlock(block, state, m_params.GetConsensus(), *this, !fJustCheck, !fJustCheck)) {
        if (state.GetResult() == BlockValidationResult::BLOCK_MUTATED) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return AbortNode(state, "Corrupt block found indicating potential hardware failure; shutting down");
        }
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    nBlocksTotal++;

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block_hash == m_params.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    // State is filled in by UpdateHashProof
    if (!UpdateHashProof(block, state, m_params.GetConsensus(), pindex, view)) {
        return error("%s: ConnectBlock(): %s", __func__, state.GetRejectReason().c_str());
    }

    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator  it = m_blockman.m_block_index.find(hashAssumeValid);
        if (it != m_blockman.m_block_index.end()) {
            if (it->second.GetAncestor(pindex->nHeight) == pindex &&
                m_chainman.m_best_header->GetAncestor(pindex->nHeight) == pindex &&
                m_chainman.m_best_header->nChainWork >= nMinimumChainWork) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // Script verification is skipped when connecting blocks under the
                // assumevalid block. Assuming the assumevalid block is valid this
                // is safe because block merkle hashes are still computed and checked,
                // Of course, if an assumed valid block is invalid due to false scriptSigs
                // this optimization would allow an invalid chain to be accepted.
                // The equivalent time check discourages hash power from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (GetBlockProofEquivalentTime(*m_chainman.m_best_header, *pindex, *m_chainman.m_best_header, m_params.GetConsensus()) <= 60 * 60 * 24 * 7 * 2);
            }
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime1 - nTimeStart), nTimeCheck * MICRO, nTimeCheck * MILLI / nBlocksTotal);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30, CVE-2012-1909, and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock);

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried it's no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.

    // BIP34 requires that a block at height X (block X) has its coinbase
    // scriptSig start with a CScriptNum of X (indicated height X).  The above
    // logic of no longer requiring BIP30 once BIP34 activates is flawed in the
    // case that there is a block X before the BIP34 height of 227,931 which has
    // an indicated height Y where Y is greater than X.  The coinbase for block
    // X would also be a valid coinbase for block Y, which could be a BIP30
    // violation.  An exhaustive search of all mainnet coinbases before the
    // BIP34 height which have an indicated height greater than the block height
    // reveals many occurrences. The 3 lowest indicated heights found are
    // 209,921, 490,897, and 1,983,702 and thus coinbases for blocks at these 3
    // heights would be the first opportunity for BIP30 to be violated.

    // The search reveals a great many blocks which have an indicated height
    // greater than 1,983,702, so we simply remove the optimization to skip
    // BIP30 checking for blocks at height 1,983,702 or higher.  Before we reach
    // that block in another 25 years or so, we should take advantage of a
    // future consensus change to do a new and improved version of BIP34 that
    // will actually prevent ever creating any duplicate coinbases in the
    // future.
    static constexpr int BIP34_IMPLIES_BIP30_LIMIT = 1983702;

    // There is no potential to create a duplicate coinbase at block 209,921
    // because this is still before the BIP34 height and so explicit BIP30
    // checking is still active.

    // The final case is block 176,684 which has an indicated height of
    // 490,897. Unfortunately, this issue was not discovered until about 2 weeks
    // before block 490,897 so there was not much opportunity to address this
    // case other than to carefully analyze it and determine it would not be a
    // problem. Block 490,897 was, in fact, mined with a different coinbase than
    // block 176,684, but it is important to note that even if it hadn't been or
    // is remined on an alternate fork with a duplicate coinbase, we would still
    // not run into a BIP30 violation.  This is because the coinbase for 176,684
    // is spent in block 185,956 in transaction
    // d4f7fbbf92f4a3014a230b2dc70b8058d02eb36ac06b4a0736d9d60eaa9e8781.  This
    // spending transaction can't be duplicated because it also spends coinbase
    // 0328dd85c331237f18e781d692c92de57649529bd5edf1d01036daea32ffde29.  This
    // coinbase has an indicated height of over 4.2 billion, and wouldn't be
    // duplicatable until that height, and it's currently impossible to create a
    // chain that long. Nevertheless we may wish to consider a future soft fork
    // which retroactively prevents block 490,897 from creating a duplicate
    // coinbase. The two historical BIP30 violations often provide a confusing
    // edge case when manipulating the UTXO and it would be simpler not to have
    // another edge case to deal with.

    // testnet3 has no blocks before the BIP34 height with indicated heights
    // post BIP34 before approximately height 486,000,000. After block
    // 1,983,702 testnet3 starts doing unnecessary BIP30 checking again.
    assert(pindex->pprev);
    CBlockIndex* pindexBIP34height = pindex->pprev->GetAncestor(m_params.GetConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == m_params.GetConsensus().BIP34Hash));

    // TODO: Remove BIP30 checking from block height 1,983,702 on, once we have a
    // consensus change that ensures coinbases at those heights cannot
    // duplicate earlier coinbases.
    if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                    LogPrintf("ERROR: ConnectBlock(): tried to overwrite transaction\n");
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-BIP30");
                }
            }
        }
    }

    // Enforce BIP68 (sequence locks)
    int nLockTimeFlags = 0;
    if (DeploymentActiveAt(*pindex, m_chainman, Consensus::DEPLOYMENT_CSV)) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Get the script flags for this block
    unsigned int flags{GetBlockScriptFlags(*pindex, m_chainman)};
    unsigned int contractflags = GetContractScriptFlags(pindex->nHeight, m_params.GetConsensus());

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime2 - nTime1), nTimeForks * MICRO, nTimeForks * MILLI / nBlocksTotal);

    CBlockUndo blockundo;

    // Precomputed transaction data pointers must not be invalidated
    // until after `control` has run the script checks (potentially
    // in multiple threads). Preallocate the vector size so a new allocation
    // doesn't invalidate pointers into the vector, and keep txsdata in scope
    // for as long as `control`.
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && g_parallel_script_checks ? &scriptcheckqueue : nullptr);
    std::vector<PrecomputedTransactionData> txsdata(block.vtx.size());

    std::vector<int> prevheights;
    CAmount nFees = 0;
    CAmount nActualStakeReward = 0;
    CAmount nValueCoinPrev = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    blockundo.vtxundo.reserve(block.vtx.size() - 1);

    ///////////////////////////////////////////////////////// // runebase
    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;
    std::vector<std::pair<CSpentIndexKey, CSpentIndexValue> > spentIndex;
    std::map<dev::Address, std::pair<CHeightTxIndexKey, std::vector<uint256>>> heightIndexes;
    /////////////////////////////////////////////////////////

    uint64_t blockGasUsed = 0;
    CAmount gasRefunds=0;

    uint64_t nValueOut=0;
    uint64_t nValueIn=0;

    if(block.IsProofOfStake())
    {
        Coin coin;
        if(!view.GetCoin(block.vtx[1]->vin[0].prevout, coin)){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "stake-prevout-not-exist", strprintf("ConnectBlock() : Stake prevout does not exist %s", block.vtx[1]->vin[0].prevout.hash.ToString()));
        }
        nValueCoinPrev = coin.out.nValue;
    }

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        if (!tx.IsCoinBase())
        {
            CAmount txfee = 0;
            TxValidationState tx_state;
            if (!Consensus::CheckTxInputs(tx, tx_state, view, pindex->nHeight, txfee)) {
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                            tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), state.ToString());
            }
            nFees += txfee;
            if (!MoneyRange(nFees)) {
                LogPrintf("ERROR: %s: accumulated fee in the block out of range.\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-accumulated-fee-outofrange");
            }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, prevheights, *pindex)) {
                LogPrintf("ERROR: %s: contains a non-BIP68-final transaction\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal");
            }

            ////////////////////////////////////////////////////////////////// // runebase
            if (fAddressIndex)
            {
                for (size_t j = 0; j < tx.vin.size(); j++) {
                    const CTxIn input = tx.vin[j];
                    const CTxOut &prevout = view.GetOutputFor(tx.vin[j]);

                    CTxDestination dest;
                    if (ExtractDestination(input.prevout, prevout.scriptPubKey, dest)) {
                        valtype bytesID(std::visit(DataVisitor(), dest));
                        if(bytesID.empty()) {
                            continue;
                        }
                        valtype addressBytes(32);
                        std::copy(bytesID.begin(), bytesID.end(), addressBytes.begin());
                        addressIndex.push_back(std::make_pair(CAddressIndexKey(dest.index(), uint256(addressBytes), pindex->nHeight, i, tx.GetHash(), j, true), prevout.nValue * -1));

                        // remove address from unspent index
                        addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(dest.index(), uint256(addressBytes), input.prevout.hash, input.prevout.n), CAddressUnspentValue()));
                        spentIndex.push_back(std::make_pair(CSpentIndexKey(input.prevout.hash, input.prevout.n), CSpentIndexValue(tx.GetHash(), j, pindex->nHeight, prevout.nValue, dest.index(), uint256(addressBytes))));
                    }
                }
            }
            //////////////////////////////////////////////////////////////////
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > dgpMaxBlockSigOps) {
            LogPrintf("ERROR: ConnectBlock(): too many sigops\n");
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops");
        }

        bool hasOpSpend = tx.HasOpSpend();

        if (!tx.IsCoinBase())
        {
            if (tx.IsCoinStake())
                nActualStakeReward = tx.GetValueOut()-view.GetValueIn(tx);
                    
            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            TxValidationState tx_state;
            if (fScriptChecks && !CheckInputScripts(tx, tx_state, view, flags, fCacheResults, fCacheResults, txsdata[i], (hasOpSpend || tx.HasCreateOrCall()) ? nullptr : (g_parallel_script_checks ? &vChecks : nullptr))) {
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                return error("ConnectBlock(): CheckInputScripts on %s failed with %s",
                    tx.GetHash().ToString(), state.ToString());
            }
            control.Add(vChecks);

            for(const CTxIn& j : tx.vin){
                if(!j.scriptSig.HasOpSpend()){
                    const CTxOut& prevout = view.AccessCoin(j.prevout).out;
                    if((prevout.scriptPubKey.HasOpCreate() || prevout.scriptPubKey.HasOpCall())){
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-invalid-contract-spend", "ConnectBlock(): Contract spend without OP_SPEND in scriptSig");
                    }
                }
            }
        }

        if(tx.IsCoinBase()){
            nValueOut += tx.GetValueOut();
        }else{
            int64_t nTxValueIn = view.GetValueIn(tx);
            int64_t nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
        }

///////////////////////////////////////////////////////////////////////////////////////// runebase
        if(!CheckOpSender(tx, m_params, pindex->nHeight)){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-invalid-sender");
        }
        if(!tx.HasOpSpend()){
            checkBlock.vtx.push_back(block.vtx[i]);
        }
        if(tx.HasCreateOrCall() && !hasOpSpend){

            if(!CheckSenderScript(view, tx)){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-invalid-sender-script");
            }

            RunebaseTxConverter convert(tx, *this, m_mempool, &view, &block.vtx, contractflags);

            ExtractRunebaseTX resultConvertRunebaseTX;
            if(!convert.extractionRunebaseTransactions(resultConvertRunebaseTX)){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-bad-contract-format", "ConnectBlock(): Contract transaction of the wrong format");
            }
            if(!CheckMinGasPrice(resultConvertRunebaseTX.second, minGasPrice))
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-low-gas-price", "ConnectBlock(): Contract execution has lower gas price than allowed");


            dev::u256 gasAllTxs = dev::u256(0);
            ByteCodeExec exec(block, resultConvertRunebaseTX.first, blockGasLimit, pindex->pprev, m_chain);
            //validate VM version and other ETH params before execution
            //Reject anything unknown (could be changed later by DGP)
            //TODO evaluate if this should be relaxed for soft-fork purposes
            bool nonZeroVersion=false;
            dev::u256 sumGas = dev::u256(0);
            CAmount nTxFee = view.GetValueIn(tx)-tx.GetValueOut();
            for(RunebaseTransaction& qtx : resultConvertRunebaseTX.first){
                sumGas += qtx.gas() * qtx.gasPrice();

                if(sumGas > dev::u256(INT64_MAX)) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-gas-stipend-overflow", "ConnectBlock(): Transaction's gas stipend overflows");
                }

                if(sumGas > dev::u256(nTxFee)) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-fee-notenough", "ConnectBlock(): Transaction fee does not cover the gas stipend");
                }

                VersionVM v = qtx.getVersion();
                if(v.format!=0)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-version-format", "ConnectBlock(): Contract execution uses unknown version format");
                if(v.rootVM != 0){
                    nonZeroVersion=true;
                }else{
                    if(nonZeroVersion){
                        //If an output is version 0, then do not allow any other versions in the same tx
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-mixed-zero-versions", "ConnectBlock(): Contract tx has mixed version 0 and non-0 VM executions");
                    }
                }
                if(!(v.rootVM == 0 || v.rootVM == 1))
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-version-rootvm", "ConnectBlock(): Contract execution uses unknown root VM");
                if(v.vmVersion != 0)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-version-vmversion", "ConnectBlock(): Contract execution uses unknown VM version");
                if(v.flagOptions != 0)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-version-flags", "ConnectBlock(): Contract execution uses unknown flag options");

                //check gas limit is not less than minimum gas limit (unless it is a no-exec tx)
                if(qtx.gas() < MINIMUM_GAS_LIMIT && v.rootVM != 0)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-too-little-gas", "ConnectBlock(): Contract execution has lower gas limit than allowed");

                if(qtx.gas() > UINT32_MAX)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-too-much-gas", "ConnectBlock(): Contract execution can not specify greater gas limit than can fit in 32-bits");

                gasAllTxs += qtx.gas();
                if(gasAllTxs > dev::u256(blockGasLimit))
                    return state.Invalid(BlockValidationResult::BLOCK_GAS_EXCEEDS_LIMIT, "bad-txns-gas-exceeds-blockgaslimit");

                //don't allow less than DGP set minimum gas price to prevent MPoS greedy mining/spammers
                if(v.rootVM!=0 && (uint64_t)qtx.gasPrice() < minGasPrice)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-low-gas-price", "ConnectBlock(): Contract execution has lower gas price than allowed");
            }

            if(!nonZeroVersion){
                //if tx is 0 version, then the tx must already have been added by a previous contract execution
                if(!tx.HasOpSpend()){
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-improper-version-0", "ConnectBlock(): Version 0 contract executions are not allowed unless created by the AAL");
                }
            }

            if(!exec.performByteCode()){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-unknown-error", "ConnectBlock(): Unknown error during contract execution");
            }

            std::vector<ResultExecute> resultExec(exec.getResult());
            ByteCodeExecResult bcer;
            if(!exec.processingResults(bcer)){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-vm-exec-processing", "ConnectBlock(): Error processing VM execution results");
            }

            std::vector<TransactionReceiptInfo> tri;
            if (fLogEvents && !fJustCheck)
            {
                uint64_t countCumulativeGasUsed = blockGasUsed;
                for(size_t k = 0; k < resultConvertRunebaseTX.first.size(); k ++){
                    for(auto& log : resultExec[k].txRec.log()) {
                        if(!heightIndexes.count(log.address)){
                            heightIndexes[log.address].first = CHeightTxIndexKey(pindex->nHeight, log.address);
                        }
                        heightIndexes[log.address].second.push_back(tx.GetHash());
                    }
                    uint64_t gasUsed = uint64_t(resultExec[k].execRes.gasUsed);
                    countCumulativeGasUsed += gasUsed;
                    tri.push_back(TransactionReceiptInfo{
                        block.GetHash(),
                        uint32_t(pindex->nHeight),
                        tx.GetHash(),
                        uint32_t(i),
                        resultConvertRunebaseTX.first[k].from(),
                        resultConvertRunebaseTX.first[k].to(),
                        countCumulativeGasUsed,
                        gasUsed,
                        resultExec[k].execRes.newAddress,
                        resultExec[k].txRec.log(),
                        resultExec[k].execRes.excepted,
                        exceptedMessage(resultExec[k].execRes.excepted, resultExec[k].execRes.output),
                        resultConvertRunebaseTX.first[k].getNVout(),
                        resultExec[k].txRec.bloom(),
                        resultExec[k].txRec.stateRoot(),
                        resultExec[k].txRec.utxoRoot(),
                    });
                }

                pstorageresult->addResult(uintToh256(tx.GetHash()), tri);
            }

            blockGasUsed += bcer.usedGas;
            if(blockGasUsed > blockGasLimit){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-gaslimit", "ConnectBlock(): Block exceeds gas limit");
            }
            for(CTxOut refundVout : bcer.refundOutputs){
                gasRefunds += refundVout.nValue;
            }
            checkVouts.insert(checkVouts.end(), bcer.refundOutputs.begin(), bcer.refundOutputs.end());
            for(CTransaction& t : bcer.valueTransfers){
                checkBlock.vtx.push_back(MakeTransactionRef(std::move(t)));
            }
            if(fRecordLogOpcodes && !fJustCheck){
                writeVMlog(resultExec, m_chain, tx, block);
            }

            for(ResultExecute& re: resultExec){
                if(re.execRes.newAddress != dev::Address() && !fJustCheck)
                    dev::g_logPost(std::string("Address : " + re.execRes.newAddress.hex()), NULL);
            }
        }
/////////////////////////////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////////////////////// // runebase
        if (fAddressIndex) {

            for (unsigned int k = 0; k < tx.vout.size(); k++) {
                const CTxOut &out = tx.vout[k];
                const bool isTxCoinStake = tx.IsCoinStake();

                CTxDestination dest;
                if (ExtractDestination({tx.GetHash(), k}, out.scriptPubKey, dest)) {
                    valtype bytesID(std::visit(DataVisitor(), dest));
                    if(bytesID.empty()) {
                        continue;
                    }
                    valtype addressBytes(32);
                    std::copy(bytesID.begin(), bytesID.end(), addressBytes.begin());
                    // record receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(dest.index(), uint256(addressBytes), pindex->nHeight, i, tx.GetHash(), k, false), out.nValue));
                    // record unspent output
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(dest.index(), uint256(addressBytes), tx.GetHash(), k), CAddressUnspentValue(out.nValue, out.scriptPubKey, pindex->nHeight, isTxCoinStake)));
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////////

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);
    }
    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

    if(nFees < gasRefunds) { //make sure it won't overflow
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-fees-greater-gasrefund", "ConnectBlock(): Less total fees than gas refund fees");
    }
    if(!CheckReward(block, state, pindex->nHeight, m_params.GetConsensus(), nFees, gasRefunds, nActualStakeReward, checkVouts, nValueCoinPrev, delegateOutputExist, m_chain, m_blockman))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "block-reward-invalid", "ConnectBlock(): Reward check failed");

    if (!control.Wait()) {
        LogPrintf("ERROR: %s: CheckQueue failed\n", __func__);
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "block-validation-failed");
    }
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n", nInputs - 1, MILLI * (nTime4 - nTime2), nInputs <= 1 ? 0 : MILLI * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * MICRO, nTimeVerify * MILLI / nBlocksTotal);

////////////////////////////////////////////////////////////////// // runebase
    if(pindex->nHeight == m_params.GetConsensus().nOfflineStakeHeight){
        globalState->deployDelegationsContract();
    }
    checkBlock.hashMerkleRoot = BlockMerkleRoot(checkBlock);
    checkBlock.hashStateRoot = h256Touint(globalState->rootHash());
    checkBlock.hashUTXORoot = h256Touint(globalState->rootHashUTXO());

    //If this error happens, it probably means that something with AAL created transactions didn't match up to what is expected
    if((checkBlock.GetHash() != block.GetHash()) && !fJustCheck)
    {
        LogPrintf("Actual block data does not match block expected by AAL\n");
        //Something went wrong with AAL, compare different elements and determine what the problem is
        if(checkBlock.hashMerkleRoot != block.hashMerkleRoot){
            //there is a mismatched tx, so go through and determine which txs
            if(block.vtx.size() > checkBlock.vtx.size()){
                LogPrintf("Unexpected AAL transactions in block. Actual txs: %i, expected txs: %i\n", block.vtx.size(), checkBlock.vtx.size());
                for(size_t i=0;i<block.vtx.size();i++){
                    if(i > checkBlock.vtx.size()-1){
                        LogPrintf("Unexpected transaction: %s\n", block.vtx[i]->ToString());
                    }else {
                        if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                            LogPrintf("Mismatched transaction at entry %i\n", i);
                            LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                            LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                        }
                    }
                }
            }else if(block.vtx.size() < checkBlock.vtx.size()){
                LogPrintf("Actual block is missing AAL transactions. Actual txs: %i, expected txs: %i\n", block.vtx.size(), checkBlock.vtx.size());
                for(size_t i=0;i<checkBlock.vtx.size();i++){
                    if(i > block.vtx.size()-1){
                        LogPrintf("Missing transaction: %s\n", checkBlock.vtx[i]->ToString());
                    }else {
                        if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                            LogPrintf("Mismatched transaction at entry %i\n", i);
                            LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                            LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                        }
                    }
                }
            }else{
                //count is correct, but a tx is wrong
                for(size_t i=0;i<checkBlock.vtx.size();i++){
                    if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                        LogPrintf("Mismatched transaction at entry %i\n", i);
                        LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                        LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                    }
                }
            }
        }
        if(checkBlock.hashUTXORoot != block.hashUTXORoot){
            LogPrintf("Actual block data does not match hashUTXORoot expected by AAL block\n");
        }
        if(checkBlock.hashStateRoot != block.hashStateRoot){
            LogPrintf("Actual block data does not match hashStateRoot expected by AAL block\n");
        }

        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "incorrect-transactions-or-hashes-block", "ConnectBlock(): Incorrect AAL transactions or hashes (hashStateRoot, hashUTXORoot)");
    }

    if (fJustCheck)
    {
        dev::h256 prevHashStateRoot(dev::sha3(dev::rlp("")));
        dev::h256 prevHashUTXORoot(dev::sha3(dev::rlp("")));
        if(pindex->pprev->hashStateRoot != uint256() && pindex->pprev->hashUTXORoot != uint256()){
            prevHashStateRoot = uintToh256(pindex->pprev->hashStateRoot);
            prevHashUTXORoot = uintToh256(pindex->pprev->hashUTXORoot);
        }
        globalState->setRoot(prevHashStateRoot);
        globalState->setRootUTXO(prevHashUTXORoot);
        return true;
    }
//////////////////////////////////////////////////////////////////

    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    //only start checking this error after block 5000 and only on testnet and mainnet, not regtest
    if(pindex->nHeight > 5000 && !m_params.MineBlocksOnDemand()) {
        //sanity check in case an exploit happens that allows new coins to be minted
        if(pindex->nMoneySupply > (uint64_t)(40499900 + ((pindex->nHeight - 5000) * 100)) * COIN){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "incorrect-money-supply", "ConnectBlock(): Unknown error caused actual money supply to exceed expected money supply");
        }
    }

    if (!m_blockman.WriteUndoDataForBlock(blockundo, state, pindex, m_params)) {
        return false;
    }

    int64_t nTime5 = GetTimeMicros(); nTimeUndo += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "    - Write undo data: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime5 - nTime4), nTimeUndo * MICRO, nTimeUndo * MILLI / nBlocksTotal);

    if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        m_blockman.m_dirty_blockindex.insert(pindex);
    }

    if (fLogEvents)
    {
        for (const auto& e: heightIndexes)
        {
            if (!m_blockman.m_block_tree_db->WriteHeightIndex(e.second.first, e.second.second))
                return AbortNode(state, "Failed to write height index");
        }
    }

    // The stake and delegate index is needed for MPoS, update it while MPoS is active
    if(pindex->nHeight <= m_params.GetConsensus().nLastMPoSBlock)
    {
        if(block.IsProofOfStake()){
            // Read the public key from the second output
            std::vector<unsigned char> vchPubKey;
            uint160 pkh;
            if(GetBlockPublicKey(block, vchPubKey))
            {
                pkh = uint160(ToByteVector(CPubKey(vchPubKey).GetID()));
                m_blockman.m_block_tree_db->WriteStakeIndex(pindex->nHeight, pkh);
            }else{
                m_blockman.m_block_tree_db->WriteStakeIndex(pindex->nHeight, uint160());
            }

            if(block.HasProofOfDelegation())
            {
                uint160 address;
                uint8_t fee = 0;
                GetBlockDelegation(block, pkh, address, fee, view, *this);
                m_blockman.m_block_tree_db->WriteDelegateIndex(pindex->nHeight, address, fee);
            }
        }else{
            m_blockman.m_block_tree_db->WriteStakeIndex(pindex->nHeight, uint160());
        }
    }

    ///////////////////////////////////////////////////////////// // runebase
    if (fAddressIndex) {
        if (!m_blockman.m_block_tree_db->WriteAddressIndex(addressIndex)) {
            return AbortNode(state, "Failed to write address index");
        }
        if (!m_blockman.m_block_tree_db->UpdateAddressUnspentIndex(addressUnspentIndex)) {
            return AbortNode(state, "Failed to write address unspent index");
        }

        if (!m_blockman.m_block_tree_db->UpdateSpentIndex(spentIndex))
            return AbortNode(state, "Failed to write transaction index");

        unsigned int logicalTS = pindex->nTime;
        unsigned int prevLogicalTS = 0;

        // retrieve logical timestamp of the previous block
        if (pindex->pprev)
            if (!m_blockman.m_block_tree_db->ReadTimestampBlockIndex(pindex->pprev->GetBlockHash(), prevLogicalTS))
                LogPrintf("%s: Failed to read previous block's logical timestamp\n", __func__);

        if (logicalTS <= prevLogicalTS) {
            logicalTS = prevLogicalTS + 1;
            LogPrint(BCLog::INDEX, "%s: Previous logical timestamp is newer Actual[%d] prevLogical[%d] Logical[%d]\n", __func__, pindex->nTime, prevLogicalTS, logicalTS);
        }

        if (!m_blockman.m_block_tree_db->WriteTimestampIndex(CTimestampIndexKey(logicalTS, pindex->GetBlockHash())))
            return AbortNode(state, "Failed to write timestamp index");

        if (!m_blockman.m_block_tree_db->WriteTimestampBlockIndex(CTimestampBlockIndexKey(pindex->GetBlockHash()), CTimestampBlockIndexValue(logicalTS)))
            return AbortNode(state, "Failed to write blockhash index");
    }
    /////////////////////////////////////////////////////////////


    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime6 = GetTimeMicros(); nTimeIndex += nTime6 - nTime5;
    LogPrint(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime6 - nTime5), nTimeIndex * MICRO, nTimeIndex * MILLI / nBlocksTotal);

    TRACE6(validation, block_connected,
        block_hash.data(),
        pindex->nHeight,
        block.vtx.size(),
        nInputs,
        nSigOpsCost,
        nTime5 - nTimeStart // in microseconds (µs)
    );

    if (fLogEvents)
        pstorageresult->commitResults();

    return true;
}

CoinsCacheSizeState Chainstate::GetCoinsCacheSizeState()
{
    AssertLockHeld(::cs_main);
    return this->GetCoinsCacheSizeState(
        m_coinstip_cache_size_bytes,
        m_mempool ? m_mempool->m_max_size_bytes : 0);
}

CoinsCacheSizeState Chainstate::GetCoinsCacheSizeState(
    size_t max_coins_cache_size_bytes,
    size_t max_mempool_size_bytes)
{
    AssertLockHeld(::cs_main);
    const int64_t nMempoolUsage = m_mempool ? m_mempool->DynamicMemoryUsage() : 0;
    int64_t cacheSize = CoinsTip().DynamicMemoryUsage() * DB_PEAK_USAGE_FACTOR;
    int64_t nTotalSpace =
        max_coins_cache_size_bytes + std::max<int64_t>(int64_t(max_mempool_size_bytes) - nMempoolUsage, 0);

    //! No need to periodic flush if at least this much space still available.
    static constexpr int64_t MAX_BLOCK_COINSDB_USAGE_BYTES = 10 * 1024 * 1024;  // 10MB
    int64_t large_threshold =
        std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE_BYTES);

    if (cacheSize > nTotalSpace) {
        LogPrintf("Cache size (%s) exceeds total space (%s)\n", cacheSize, nTotalSpace);
        return CoinsCacheSizeState::CRITICAL;
    } else if (cacheSize > large_threshold) {
        return CoinsCacheSizeState::LARGE;
    }
    return CoinsCacheSizeState::OK;
}

bool Chainstate::FlushStateToDisk(
    BlockValidationState &state,
    FlushStateMode mode,
    int nManualPruneHeight)
{
    LOCK(cs_main);
    assert(this->CanFlushToDisk());
    static std::chrono::microseconds nLastWrite{0};
    static std::chrono::microseconds nLastFlush{0};
    std::set<int> setFilesToPrune;
    bool full_flush_completed = false;

    const size_t coins_count = CoinsTip().GetCacheSize();
    const size_t coins_mem_usage = CoinsTip().DynamicMemoryUsage();

    try {
    {
        bool fFlushForPrune = false;
        bool fDoFullFlush = false;

        CoinsCacheSizeState cache_state = GetCoinsCacheSizeState();
        LOCK(m_blockman.cs_LastBlockFile);
        if (fPruneMode && (m_blockman.m_check_for_pruning || nManualPruneHeight > 0) && !fReindex) {
            // make sure we don't prune above any of the prune locks bestblocks
            // pruning is height-based
            int last_prune{m_chain.Height()}; // last height we can prune
            std::optional<std::string> limiting_lock; // prune lock that actually was the limiting factor, only used for logging

            for (const auto& prune_lock : m_blockman.m_prune_locks) {
                if (prune_lock.second.height_first == std::numeric_limits<int>::max()) continue;
                // Remove the buffer and one additional block here to get actual height that is outside of the buffer
                const int lock_height{prune_lock.second.height_first - PRUNE_LOCK_BUFFER - 1};
                last_prune = std::max(1, std::min(last_prune, lock_height));
                if (last_prune == lock_height) {
                    limiting_lock = prune_lock.first;
                }
            }

            if (limiting_lock) {
                LogPrint(BCLog::PRUNE, "%s limited pruning to height %d\n", limiting_lock.value(), last_prune);
            }

            if (nManualPruneHeight > 0) {
                LOG_TIME_MILLIS_WITH_CATEGORY("find files to prune (manual)", BCLog::BENCH);

                m_blockman.FindFilesToPruneManual(setFilesToPrune, std::min(last_prune, nManualPruneHeight), m_chain.Height());
            } else {
                LOG_TIME_MILLIS_WITH_CATEGORY("find files to prune", BCLog::BENCH);

                m_blockman.FindFilesToPrune(setFilesToPrune, m_params.PruneAfterHeight(), m_chain.Height(), last_prune, IsInitialBlockDownload());
                m_blockman.m_check_for_pruning = false;
            }
            if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!m_blockman.m_have_pruned) {
                    m_blockman.m_block_tree_db->WriteFlag("prunedblockfiles", true);
                    m_blockman.m_have_pruned = true;
                }
            }
        }
        const auto nNow = GetTime<std::chrono::microseconds>();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite.count() == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush.count() == 0) {
            nLastFlush = nNow;
        }
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FlushStateMode::PERIODIC && cache_state >= CoinsCacheSizeState::LARGE;
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FlushStateMode::IF_NEEDED && cache_state >= CoinsCacheSizeState::CRITICAL;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FlushStateMode::PERIODIC && nNow > nLastWrite + DATABASE_WRITE_INTERVAL;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FlushStateMode::PERIODIC && nNow > nLastFlush + DATABASE_FLUSH_INTERVAL;
        // Combine all conditions that result in a full cache flush.
        fDoFullFlush = (mode == FlushStateMode::ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Ensure we can write block index
            if (!CheckDiskSpace(gArgs.GetBlocksDirPath())) {
                return AbortNode(state, "Disk space is too low!", _("Disk space is too low!"));
            }
            {
                LOG_TIME_MILLIS_WITH_CATEGORY("write block and undo data to disk", BCLog::BENCH);

                // First make sure all block and undo data is flushed to disk.
                m_blockman.FlushBlockFile();
            }

            // Then update all block file information (which may refer to block and undo files).
            {
                LOG_TIME_MILLIS_WITH_CATEGORY("write block index to disk", BCLog::BENCH);

                if (!m_blockman.WriteBlockIndexDB()) {
                    return AbortNode(state, "Failed to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune) {
                LOG_TIME_MILLIS_WITH_CATEGORY("unlink pruned files", BCLog::BENCH);

                UnlinkPrunedFiles(setFilesToPrune);
            }
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush && !CoinsTip().GetBestBlock().IsNull()) {
            LOG_TIME_MILLIS_WITH_CATEGORY(strprintf("write coins cache to disk (%d coins, %.2fkB)",
                coins_count, coins_mem_usage / 1000), BCLog::BENCH);

            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(gArgs.GetDataDirNet(), 48 * 2 * 2 * CoinsTip().GetCacheSize())) {
                return AbortNode(state, "Disk space is too low!", _("Disk space is too low!"));
            }
            // Flush the chainstate (which may refer to block index entries).
            if (!CoinsTip().Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
            full_flush_completed = true;
            TRACE5(utxocache, flush,
                   (int64_t)(GetTimeMicros() - nNow.count()), // in microseconds (µs)
                   (uint32_t)mode,
                   (uint64_t)coins_count,
                   (uint64_t)coins_mem_usage,
                   (bool)fFlushForPrune);
        }
    }
    if (full_flush_completed) {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().ChainStateFlushed(m_chain.GetLocator());
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void Chainstate::ForceFlushStateToDisk()
{
    BlockValidationState state;
    if (!this->FlushStateToDisk(state, FlushStateMode::ALWAYS)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

void Chainstate::PruneAndFlush()
{
    BlockValidationState state;
    m_blockman.m_check_for_pruning = true;
    if (!this->FlushStateToDisk(state, FlushStateMode::NONE)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

static void DoWarning(const bilingual_str& warning)
{
    static bool fWarned = false;
    SetMiscWarning(warning);
    if (!fWarned) {
        AlertNotify(warning.original);
        fWarned = true;
    }
}

/** Private helper function that concatenates warning messages. */
static void AppendWarning(bilingual_str& res, const bilingual_str& warn)
{
    if (!res.empty()) res += Untranslated(", ");
    res += warn;
}

static void UpdateTipLog(
    const CCoinsViewCache& coins_tip,
    const CBlockIndex* tip,
    const CChainParams& params,
    const std::string& func_name,
    const std::string& prefix,
    const std::string& warning_messages) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{

    AssertLockHeld(::cs_main);
    LogPrintf("%s%s: new best=%s height=%d version=0x%08x log2_work=%f tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)%s\n",
        prefix, func_name,
        tip->GetBlockHash().ToString(), tip->nHeight, tip->nVersion,
        log(tip->nChainWork.getdouble()) / log(2.0), (unsigned long)tip->nChainTx,
        FormatISO8601DateTime(tip->GetBlockTime()),
        GuessVerificationProgress(params.TxData(), tip),
        coins_tip.DynamicMemoryUsage() * (1.0 / (1 << 20)),
        coins_tip.GetCacheSize(),
        !warning_messages.empty() ? strprintf(" warning='%s'", warning_messages) : "");
}

void Chainstate::UpdateTip(const CBlockIndex* pindexNew)
{
    AssertLockHeld(::cs_main);
    const auto& coins_tip = this->CoinsTip();

    // The remainder of the function isn't relevant if we are not acting on
    // the active chainstate, so return if need be.
    if (this != &m_chainman.ActiveChainstate()) {
        // Only log every so often so that we don't bury log messages at the tip.
        constexpr int BACKGROUND_LOG_INTERVAL = 2000;
        if (pindexNew->nHeight % BACKGROUND_LOG_INTERVAL == 0) {
            UpdateTipLog(coins_tip, pindexNew, m_params, __func__, "[background validation] ", "");
        }
        return;
    }

    // New best block
    if (m_mempool) {
        m_mempool->AddTransactionsUpdated(1);
    }

    {
        LOCK(g_best_block_mutex);
        g_best_block = pindexNew->GetBlockHash();
        g_best_block_cv.notify_all();
    }

    bilingual_str warning_messages;
    if (!this->IsInitialBlockDownload()) {
        const CBlockIndex* pindex = pindexNew;
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(m_chainman, bit);
            ThresholdState state = checker.GetStateFor(pindex, m_params.GetConsensus(), warningcache.at(bit));
            if (state == ThresholdState::ACTIVE || state == ThresholdState::LOCKED_IN) {
                const bilingual_str warning = strprintf(_("Unknown new rules activated (versionbit %i)"), bit);
                if (state == ThresholdState::ACTIVE) {
                    DoWarning(warning);
                } else {
                    AppendWarning(warning_messages, warning);
                }
            }
        }
    }
    UpdateTipLog(coins_tip, pindexNew, m_params, __func__, "", warning_messages.original);
}

/** Disconnect m_chain's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling MaybeUpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool Chainstate::DisconnectTip(BlockValidationState& state, DisconnectedBlockTransactions* disconnectpool)
{
    AssertLockHeld(cs_main);
    if (m_mempool) AssertLockHeld(m_mempool->cs);

    CBlockIndex *pindexDelete = m_chain.Tip();
    assert(pindexDelete);
    assert(pindexDelete->pprev);
    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete, m_params.GetConsensus())) {
        return error("DisconnectTip(): Failed to read block");
    }
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(&CoinsTip());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view, nullptr) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
    }
    LogPrint(BCLog::BENCH, "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * MILLI);

    {
        // Prune locks that began at or after the tip should be moved backward so they get a chance to reorg
        const int max_height_first{pindexDelete->nHeight - 1};
        for (auto& prune_lock : m_blockman.m_prune_locks) {
            if (prune_lock.second.height_first <= max_height_first) continue;

            prune_lock.second.height_first = max_height_first;
            LogPrint(BCLog::PRUNE, "%s prune lock moved back to %d\n", prune_lock.first, max_height_first);
        }
    }

    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FlushStateMode::IF_NEEDED)) {
        return false;
    }

    if (disconnectpool && m_mempool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }
        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            m_mempool->removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    m_chain.SetTip(*pindexDelete->pprev);

    UpdateTip(pindexDelete->pprev);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    GetMainSignals().BlockDisconnected(pblock, pindexDelete);
    return true;
}

static int64_t nTimeReadFromDiskTotal = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

struct PerBlockConnectTrace {
    CBlockIndex* pindex = nullptr;
    std::shared_ptr<const CBlock> pblock;
    PerBlockConnectTrace() = default;
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class is single-use, once you call GetBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;

public:
    explicit ConnectTrace() : blocksConnected(1) {}

    void BlockConnected(CBlockIndex* pindex, std::shared_ptr<const CBlock> pblock) {
        assert(!blocksConnected.back().pindex);
        assert(pindex);
        assert(pblock);
        blocksConnected.back().pindex = pindex;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& GetBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pindex);
        blocksConnected.pop_back();
        return blocksConnected;
    }
};

/**
 * Connect a new block to m_chain. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool Chainstate::ConnectTip(BlockValidationState& state, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions& disconnectpool)
{
    AssertLockHeld(cs_main);
    if (m_mempool) AssertLockHeld(m_mempool->cs);

    assert(pindexNew->pprev == m_chain.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, m_params.GetConsensus())) {
            return AbortNode(state, "Failed to read block");
        }
        pthisBlock = pblockNew;
    } else {
        LogPrint(BCLog::BENCH, "  - Using cached block\n");
        pthisBlock = pblock;
    }
    const CBlock& blockConnecting = *pthisBlock;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDiskTotal += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(BCLog::BENCH, "  - Load block from disk: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime2 - nTime1) * MILLI, nTimeReadFromDiskTotal * MICRO, nTimeReadFromDiskTotal * MILLI / nBlocksTotal);
    {
        CCoinsViewCache view(&CoinsTip());

        dev::h256 oldHashStateRoot(globalState->rootHash()); // runebase
        dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // runebase

        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);

            globalState->setRoot(oldHashStateRoot); // runebase
            globalState->setRootUTXO(oldHashUTXORoot); // runebase
            pstorageresult->clearCacheResult();
            return error("%s: ConnectBlock %s failed, %s", __func__, pindexNew->GetBlockHash().ToString(), state.ToString());
        }
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        assert(nBlocksTotal > 0);
        LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime3 - nTime2) * MILLI, nTimeConnectTotal * MICRO, nTimeConnectTotal * MILLI / nBlocksTotal);
        bool flushed = view.Flush();
        assert(flushed);
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCH, "  - Flush: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime4 - nTime3) * MILLI, nTimeFlush * MICRO, nTimeFlush * MILLI / nBlocksTotal);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FlushStateMode::IF_NEEDED)) {
        return false;
    }
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "  - Writing chainstate: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime5 - nTime4) * MILLI, nTimeChainState * MICRO, nTimeChainState * MILLI / nBlocksTotal);
    // Remove conflicting transactions from the mempool.;
    if (m_mempool) {
        m_mempool->removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
        disconnectpool.removeForBlock(blockConnecting.vtx);
    }
    // Update m_chain & related variables.
    m_chain.SetTip(*pindexNew);
    UpdateTip(pindexNew);

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCH, "  - Connect postprocess: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime5) * MILLI, nTimePostConnect * MICRO, nTimePostConnect * MILLI / nBlocksTotal);
    LogPrint(BCLog::BENCH, "- Connect block: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime1) * MILLI, nTimeTotal * MICRO, nTimeTotal * MILLI / nBlocksTotal);

    connectTrace.BlockConnected(pindexNew, std::move(pthisBlock));
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex* Chainstate::FindMostWorkChain()
{
    AssertLockHeld(::cs_main);
    do {
        CBlockIndex *pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !m_chain.Contains(pindexTest)) {
            assert(pindexTest->HaveTxsDownloaded() || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (m_chainman.m_best_invalid == nullptr || pindexNew->nChainWork > m_chainman.m_best_invalid->nChainWork)) {
                    m_chainman.m_best_invalid = pindexNew;
                }
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to m_blocks_unlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        m_blockman.m_blocks_unlinked.insert(
                            std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void Chainstate::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, m_chain.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 *
 * @returns true unless a system error occurred
 */
bool Chainstate::ActivateBestChainStep(BlockValidationState& state, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);
    if (m_mempool) AssertLockHeld(m_mempool->cs);

    const CBlockIndex* pindexOldTip = m_chain.Tip();
    const CBlockIndex* pindexFork = m_chain.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (m_chain.Tip() && m_chain.Tip() != pindexFork) {
        if (!DisconnectTip(state, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            MaybeUpdateMempoolForReorg(disconnectpool, false);

            // If we're unable to disconnect a block during normal operation,
            // then that is a failure of our local system -- we should abort
            // rather than stay on a less work chain.
            AbortNode(state, "Failed to disconnect block; see debug.log for details");
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect (in descending height order).
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex* pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex* pindexConnect : reverse_iterate(vpindexToConnect)) {
            if (!ConnectTip(state, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
                        InvalidChainFound(vpindexToConnect.front());
                    }
                    state = BlockValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    MaybeUpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || m_chain.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        MaybeUpdateMempoolForReorg(disconnectpool, true);
    }
    if (m_mempool) m_mempool->check(this->CoinsTip(), this->m_chain.Height() + 1);

    CheckForkWarningConditions();

    return true;
}

static SynchronizationState GetSynchronizationState(bool init)
{
    if (!init) return SynchronizationState::POST_INIT;
    if (::fReindex) return SynchronizationState::INIT_REINDEX;
    return SynchronizationState::INIT_DOWNLOAD;
}

static bool NotifyHeaderTip(Chainstate& chainstate) LOCKS_EXCLUDED(cs_main) {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = nullptr;
    CBlockIndex* pindexHeader = nullptr;
    {
        LOCK(cs_main);
        pindexHeader = chainstate.m_chainman.m_best_header;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = chainstate.IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(GetSynchronizationState(fInitialBlockDownload), pindexHeader->nHeight, pindexHeader->nTime, false);
    }
    return fNotify;
}

static void LimitValidationInterfaceQueue() LOCKS_EXCLUDED(cs_main) {
    AssertLockNotHeld(cs_main);

    if (GetMainSignals().CallbacksPending() > 10) {
        SyncWithValidationInterfaceQueue();
    }
}

bool Chainstate::ActivateBestChain(BlockValidationState& state, std::shared_ptr<const CBlock> pblock)
{
    AssertLockNotHeld(m_chainstate_mutex);

    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(::cs_main);

    // ABC maintains a fair degree of expensive-to-calculate internal state
    // because this function periodically releases cs_main so that it does not lock up other threads for too long
    // during large connects - and to allow for e.g. the callback queue to drain
    // we use m_chainstate_mutex to enforce mutual exclusion so that only one caller may execute this function at a time
    LOCK(m_chainstate_mutex);

    CBlockIndex *pindexMostWork = nullptr;
    CBlockIndex *pindexNewTip = nullptr;
    int nStopAtHeight = gArgs.GetIntArg("-stopatheight", DEFAULT_STOPATHEIGHT);
    do {
        // Block until the validation queue drains. This should largely
        // never happen in normal operation, however may happen during
        // reindex, causing memory blowup if we run too far ahead.
        // Note that if a validationinterface callback ends up calling
        // ActivateBestChain this may lead to a deadlock! We should
        // probably have a DEBUG_LOCKORDER test for this in the future.
        LimitValidationInterfaceQueue();

        {
            LOCK(cs_main);
            // Lock transaction pool for at least as long as it takes for connectTrace to be consumed
            LOCK(MempoolMutex());
            CBlockIndex* starting_tip = m_chain.Tip();
            bool blocks_connected = false;
            do {
                // We absolutely may not unlock cs_main until we've made forward progress
                // (with the exception of shutdown due to hardware issues, low disk space, etc).
                ConnectTrace connectTrace; // Destructed before cs_main is unlocked

                if (pindexMostWork == nullptr) {
                    pindexMostWork = FindMostWorkChain();
                }

                // Whether we have anything to do at all.
                if (pindexMostWork == nullptr || pindexMostWork == m_chain.Tip()) {
                    break;
                }

                bool fInvalidFound = false;
                std::shared_ptr<const CBlock> nullBlockPtr;
                if (!ActivateBestChainStep(state, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace)) {
                    // A system error occurred
                    return false;
                }
                blocks_connected = true;

                if (fInvalidFound) {
                    // Wipe cache, we may need another branch now.
                    pindexMostWork = nullptr;
                }
                pindexNewTip = m_chain.Tip();

                for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                    assert(trace.pblock && trace.pindex);
                    GetMainSignals().BlockConnected(trace.pblock, trace.pindex);
                }
            } while (!m_chain.Tip() || (starting_tip && CBlockIndexWorkComparator()(m_chain.Tip(), starting_tip)));
            if (!blocks_connected) return true;

            const CBlockIndex* pindexFork = m_chain.FindFork(starting_tip);
            bool fInitialDownload = IsInitialBlockDownload();

            // Notify external listeners about the new tip.
            // Enqueue while holding cs_main to ensure that UpdatedBlockTip is called in the order in which blocks are connected
            if (pindexFork != pindexNewTip) {
                // Notify ValidationInterface subscribers
                GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

                // Always notify the UI if a new block tip was connected
                uiInterface.NotifyBlockTip(GetSynchronizationState(fInitialDownload), pindexNewTip);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        if (nStopAtHeight && pindexNewTip && pindexNewTip->nHeight >= nStopAtHeight) StartShutdown();

        // We check shutdown only after giving ActivateBestChainStep a chance to run once so that we
        // never shutdown before connecting the genesis block during LoadChainTip(). Previously this
        // caused an assert() failure during shutdown in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (ShutdownRequested()) break;
    } while (pindexNewTip != pindexMostWork);
    CheckBlockIndex();

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FlushStateMode::PERIODIC)) {
        return false;
    }

    return true;
}

bool Chainstate::PreciousBlock(BlockValidationState& state, CBlockIndex* pindex)
{
    AssertLockNotHeld(m_chainstate_mutex);
    AssertLockNotHeld(::cs_main);
    {
        LOCK(cs_main);
        if (pindex->nChainWork < m_chain.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        }
        if (m_chain.Tip()->nChainWork > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        }
        nLastPreciousChainwork = m_chain.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->HaveTxsDownloaded()) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, std::shared_ptr<const CBlock>());
}

bool Chainstate::InvalidateBlock(BlockValidationState& state, CBlockIndex* pindex)
{
    AssertLockNotHeld(m_chainstate_mutex);
    AssertLockNotHeld(::cs_main);

    // Genesis block can't be invalidated
    assert(pindex);
    if (pindex->nHeight == 0) return false;

    CBlockIndex* to_mark_failed = pindex;
    bool pindex_was_in_chain = false;
    int disconnected = 0;

    // We do not allow ActivateBestChain() to run while InvalidateBlock() is
    // running, as that could cause the tip to change while we disconnect
    // blocks.
    LOCK(m_chainstate_mutex);

    // We'll be acquiring and releasing cs_main below, to allow the validation
    // callbacks to run. However, we should keep the block index in a
    // consistent state as we disconnect blocks -- in particular we need to
    // add equal-work blocks to setBlockIndexCandidates as we disconnect.
    // To avoid walking the block index repeatedly in search of candidates,
    // build a map once so that we can look up candidate blocks by chain
    // work as we go.
    std::multimap<const arith_uint256, CBlockIndex *> candidate_blocks_by_work;

    {
        LOCK(cs_main);
        for (auto& entry : m_blockman.m_block_index) {
            CBlockIndex* candidate = &entry.second;
            // We don't need to put anything in our active chain into the
            // multimap, because those candidates will be found and considered
            // as we disconnect.
            // Instead, consider only non-active-chain blocks that have at
            // least as much work as where we expect the new tip to end up.
            if (!m_chain.Contains(candidate) &&
                    !CBlockIndexWorkComparator()(candidate, pindex->pprev) &&
                    candidate->IsValid(BLOCK_VALID_TRANSACTIONS) &&
                    candidate->HaveTxsDownloaded()) {
                candidate_blocks_by_work.insert(std::make_pair(candidate->nChainWork, candidate));
            }
        }
    }

    // Disconnect (descendants of) pindex, and mark them invalid.
    while (true) {
        if (ShutdownRequested()) break;

        // Make sure the queue of validation callbacks doesn't grow unboundedly.
        LimitValidationInterfaceQueue();

        LOCK(cs_main);
        // Lock for as long as disconnectpool is in scope to make sure MaybeUpdateMempoolForReorg is
        // called after DisconnectTip without unlocking in between
        LOCK(MempoolMutex());
        if (!m_chain.Contains(pindex)) break;
        pindex_was_in_chain = true;
        CBlockIndex *invalid_walk_tip = m_chain.Tip();

        // ActivateBestChain considers blocks already in m_chain
        // unconditionally valid already, so force disconnect away from it.
        DisconnectedBlockTransactions disconnectpool;
        bool ret = DisconnectTip(state, &disconnectpool);
        // DisconnectTip will add transactions to disconnectpool.
        // Adjust the mempool to be consistent with the new tip, adding
        // transactions back to the mempool if disconnecting was successful,
        // and we're not doing a very deep invalidation (in which case
        // keeping the mempool up to date is probably futile anyway).
        MaybeUpdateMempoolForReorg(disconnectpool, /* fAddToMempool = */ (++disconnected <= 10) && ret);
        if (!ret) return false;
        assert(invalid_walk_tip->pprev == m_chain.Tip());

        // We immediately mark the disconnected blocks as invalid.
        // This prevents a case where pruned nodes may fail to invalidateblock
        // and be left unable to start as they have no tip candidates (as there
        // are no blocks that meet the "have data and are not invalid per
        // nStatus" criteria for inclusion in setBlockIndexCandidates).
        invalid_walk_tip->nStatus |= BLOCK_FAILED_VALID;
        m_blockman.m_dirty_blockindex.insert(invalid_walk_tip);
        setBlockIndexCandidates.erase(invalid_walk_tip);
        setBlockIndexCandidates.insert(invalid_walk_tip->pprev);
        if (invalid_walk_tip->pprev == to_mark_failed && (to_mark_failed->nStatus & BLOCK_FAILED_VALID)) {
            // We only want to mark the last disconnected block as BLOCK_FAILED_VALID; its children
            // need to be BLOCK_FAILED_CHILD instead.
            to_mark_failed->nStatus = (to_mark_failed->nStatus ^ BLOCK_FAILED_VALID) | BLOCK_FAILED_CHILD;
            m_blockman.m_dirty_blockindex.insert(to_mark_failed);
        }

        // Add any equal or more work headers to setBlockIndexCandidates
        auto candidate_it = candidate_blocks_by_work.lower_bound(invalid_walk_tip->pprev->nChainWork);
        while (candidate_it != candidate_blocks_by_work.end()) {
            if (!CBlockIndexWorkComparator()(candidate_it->second, invalid_walk_tip->pprev)) {
                setBlockIndexCandidates.insert(candidate_it->second);
                candidate_it = candidate_blocks_by_work.erase(candidate_it);
            } else {
                ++candidate_it;
            }
        }

        // Track the last disconnected block, so we can correct its BLOCK_FAILED_CHILD status in future
        // iterations, or, if it's the last one, call InvalidChainFound on it.
        to_mark_failed = invalid_walk_tip;
    }

    CheckBlockIndex();

    {
        LOCK(cs_main);
        if (m_chain.Contains(to_mark_failed)) {
            // If the to-be-marked invalid block is in the active chain, something is interfering and we can't proceed.
            return false;
        }

        // Mark pindex (or the last disconnected block) as invalid, even when it never was in the main chain
        to_mark_failed->nStatus |= BLOCK_FAILED_VALID;
        m_blockman.m_dirty_blockindex.insert(to_mark_failed);
        setBlockIndexCandidates.erase(to_mark_failed);
        m_chainman.m_failed_blocks.insert(to_mark_failed);

        // If any new blocks somehow arrived while we were disconnecting
        // (above), then the pre-calculation of what should go into
        // setBlockIndexCandidates may have missed entries. This would
        // technically be an inconsistency in the block index, but if we clean
        // it up here, this should be an essentially unobservable error.
        // Loop back over all block index entries and add any missing entries
        // to setBlockIndexCandidates.
        for (auto& [_, block_index] : m_blockman.m_block_index) {
            if (block_index.IsValid(BLOCK_VALID_TRANSACTIONS) && block_index.HaveTxsDownloaded() && !setBlockIndexCandidates.value_comp()(&block_index, m_chain.Tip())) {
                setBlockIndexCandidates.insert(&block_index);
            }
        }

        InvalidChainFound(to_mark_failed);
    }

    // Only notify about a new block tip if the active chain was modified.
    if (pindex_was_in_chain) {
        uiInterface.NotifyBlockTip(GetSynchronizationState(IsInitialBlockDownload()), to_mark_failed->pprev);
    }
    return true;
}

void Chainstate::ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    for (auto& [_, block_index] : m_blockman.m_block_index) {
        if (!block_index.IsValid() && block_index.GetAncestor(nHeight) == pindex) {
            block_index.nStatus &= ~BLOCK_FAILED_MASK;
            m_blockman.m_dirty_blockindex.insert(&block_index);
            if (block_index.IsValid(BLOCK_VALID_TRANSACTIONS) && block_index.HaveTxsDownloaded() && setBlockIndexCandidates.value_comp()(m_chain.Tip(), &block_index)) {
                setBlockIndexCandidates.insert(&block_index);
            }
            if (&block_index == m_chainman.m_best_invalid) {
                // Reset invalid block marker if it was pointing to one of those.
                m_chainman.m_best_invalid = nullptr;
            }
            m_chainman.m_failed_blocks.erase(&block_index);
        }
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            m_blockman.m_dirty_blockindex.insert(pindex);
            m_chainman.m_failed_blocks.erase(pindex);
        }
        pindex = pindex->pprev;
    }
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
void Chainstate::ReceivedBlockTransactions(const CBlock& block, CBlockIndex* pindexNew, const FlatFilePos& pos)
{
    AssertLockHeld(cs_main);
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (DeploymentActiveAt(*pindexNew, m_chainman, Consensus::DEPLOYMENT_SEGWIT)) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    m_blockman.m_dirty_blockindex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->HaveTxsDownloaded()) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            pindex->nSequenceId = nBlockSequenceId++;
            if (m_chain.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, m_chain.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = m_blockman.m_blocks_unlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                m_blockman.m_blocks_unlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            m_blockman.m_blocks_unlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }
}

bool CheckFirstCoinstakeOutput(const CBlock& block)
{
    // Coinbase output should be empty if proof-of-stake block
    int commitpos = GetWitnessCommitmentIndex(block);
    if(commitpos < 0)
    {
        if (block.vtx[0]->vout.size() != 1 || !block.vtx[0]->vout[0].IsEmpty())
            return false;
    }
    else
    {
        if (block.vtx[0]->vout.size() != 2 || !block.vtx[0]->vout[0].IsEmpty() || block.vtx[0]->vout[1].nValue)
            return false;
    }

    return true;
}

bool GetBlockPublicKey(const CBlock& block, std::vector<unsigned char>& vchPubKey)
{
    if (block.IsProofOfWork())
        return false;

    if (block.vchBlockSigDlgt.empty())
        return false;

    std::vector<valtype> vSolutions;
    const CTxOut& txout = block.vtx[1]->vout[1];
    TxoutType whichType = Solver(txout.scriptPubKey, vSolutions);

    if (whichType == TxoutType::NONSTANDARD)
        return false;

    if (whichType == TxoutType::PUBKEY)
    {
        vchPubKey = vSolutions[0];
        return true;
    }
    else
    {
        // Block signing key also can be encoded in the nonspendable output
        // This allows to not pollute UTXO set with useless outputs e.g. in case of multisig staking

        const CScript& script = txout.scriptPubKey;
        CScript::const_iterator pc = script.begin();
        opcodetype opcode;
        valtype vchPushValue;

        if (!script.GetOp(pc, opcode, vchPubKey))
            return false;
        if (opcode != OP_RETURN)
            return false;
        if (!script.GetOp(pc, opcode, vchPubKey))
            return false;
        if (!IsCompressedOrUncompressedPubKey(vchPubKey))
            return false;
        return true;
    }

    return false;
}

bool GetBlockDelegation(const CBlock& block, const uint160& staker, uint160& address, uint8_t& fee, CCoinsViewCache& view, Chainstate& chainstate)
{
    // Check block parameters
    if (block.IsProofOfWork())
        return false;

    if (block.vchBlockSigDlgt.empty())
        return false;

    if (!block.HasProofOfDelegation())
        return false;

    if(block.vtx.size() < 1)
        return false;

    // Get the delegate
    std::string strMessage = staker.GetReverseHex();
    CKeyID keyid;
    if(!SignStr::GetKeyIdMessage(strMessage, block.GetProofOfDelegation(), keyid))
        return false;
    address = uint160(keyid);

    // Get the fee from the delegation contract
    uint8_t inFee = 0;
    if(!GetDelegationFeeFromContract(address, inFee, chainstate))
        return false;

    bool delegateOutputExist = IsDelegateOutputExist(inFee);
    size_t minVoutSize = delegateOutputExist ? 3 : 2;
    if(block.vtx[1]->vin.size() < 1 ||
            block.vtx[1]->vout.size() < minVoutSize)
        return false;

    // Get the staker fee
    COutPoint prevout = block.vtx[1]->vin[0].prevout;
    CAmount nValueCoin = view.AccessCoin(prevout).out.nValue;
    if(nValueCoin <= 0)
        return false;

    CAmount nValueStaker = block.vtx[1]->vout[1].nValue - nValueCoin;
    CAmount nValueDelegate = delegateOutputExist ? block.vtx[1]->vout[2].nValue : 0;
    CAmount nReward = nValueStaker + nValueDelegate;
    if(nReward <= 0)
        return false;

    fee = (nValueStaker * 100 + nReward - 1) / nReward;
    if(inFee != fee)
        return false;

    return true;
}

bool CheckBlockSignature(const CBlock& block)
{
    std::vector<unsigned char> vchBlockSig = block.GetBlockSignature();
    if (block.IsProofOfWork())
        return vchBlockSig.empty();

    std::vector<unsigned char> vchPubKey;
    if(!GetBlockPublicKey(block, vchPubKey))
    {
        return false;
    }

    uint256 hash = block.GetHashWithoutSign();

    if(vchBlockSig.size() == CPubKey::COMPACT_SIGNATURE_SIZE)
    {
        CPubKey pubkey;
        if(pubkey.RecoverCompact(hash, vchBlockSig) && pubkey == CPubKey(vchPubKey))
            return true;
    }

    return CPubKey(vchPubKey).Verify(hash, vchBlockSig);
}

static bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, Chainstate& chainstate, bool fCheckPOW = true, bool fCheckPOS = true)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && block.IsProofOfWork() && !CheckHeaderPoW(block, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash", "proof of work failed");

    // Check proof of stake matches claimed amount
    if (fCheckPOS && !chainstate.IsInitialBlockDownload() && block.IsProofOfStake() && !CheckHeaderPoS(block, consensusParams, chainstate))
        // May occur if behind on block chain sync
       return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-cb-header", "proof of stake failed");

    return true;
}

bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, Chainstate& chainstate, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, chainstate, fCheckPOW, false))
        return false;

    if (block.IsProofOfStake() &&  block.GetBlockTime() > FutureDrift(GetAdjustedTimeSeconds(), chainstate.m_chain.Height() + 1, consensusParams))
        return error("CheckBlock() : block timestamp too far in the future");

    // Signet only: check block solution
    if (consensusParams.signet_blocks && fCheckPOW && !CheckSignetBlockSolution(block, consensusParams)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-signet-blksig", "signet block signature validation failure");
    }

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-txnmrklroot", "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-txns-duplicate", "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "more than one coinbase");

    //Don't allow contract opcodes in coinbase
    if(block.vtx[0]->HasOpSpend() || block.vtx[0]->HasCreateOrCall() || block.vtx[0]->HasOpSender()){
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-contract", "coinbase must not contain OP_SPEND, OP_CALL, OP_CREATE or OP_SENDER");
    }

    // Second transaction must be coinbase in case of PoS block, the rest must not be
    if (block.IsProofOfStake())
    {
        // Coinbase output should be empty if proof-of-stake block
        if (!CheckFirstCoinstakeOutput(block))
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "coinbase output not empty for proof-of-stake block");

        // Second transaction must be coinstake
        if (block.vtx.empty() || block.vtx.size() < 2 || !block.vtx[1]->IsCoinStake())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-missing", "second tx is not coinstake");

        if(!block.HasProofOfDelegation())
        {
            //prevoutStake must exactly match the coinstake in the block body
            if(block.vtx[1]->vin.empty() || block.prevoutStake != block.vtx[1]->vin[0].prevout){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-invalid", "prevoutStake in block header does not match coinstake in block body");
            }
        }
        //the rest of the transactions must not be coinstake
        for (unsigned int i = 2; i < block.vtx.size(); i++)
            if (block.vtx[i]->IsCoinStake())
               return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-multiple", "more than one coinstake");

        //Don't allow contract opcodes in coinstake
        //We might allow this later, but it hasn't been tested enough to determine if safe
        if(block.vtx[1]->HasOpSpend() || block.vtx[1]->HasCreateOrCall() || block.vtx[1]->HasOpSender()){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-contract", "coinstake must not contain OP_SPEND, OP_CALL, OP_CREATE or OP_SENDER");
        }
    }

    // Check proof-of-stake block signature
    if (fCheckSig && !CheckBlockSignature(block))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-signature", "bad proof-of-stake block signature");

    bool lastWasContract=false;
    // Check transactions
    // Must check for duplicate inputs (see CVE-2018-17144)
    for (const auto& tx : block.vtx) {
        TxValidationState tx_state;
        if (!CheckTransaction(*tx, tx_state)) {
            // CheckBlock() does context-free validation checks. The only
            // possible failures are consensus failures.
            assert(tx_state.GetResult() == TxValidationResult::TX_CONSENSUS);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), tx_state.GetDebugMessage()));
        }
        //OP_SPEND can only exist immediately after a contract tx in a block, or after another OP_SPEND
        //So, if the previous tx was not a contract tx, fail it.
        if(tx->HasOpSpend()){
            if(!lastWasContract){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-opspend-tx", "OP_SPEND transaction without corresponding contract transaction");
            }
        }
        lastWasContract = tx->HasCreateOrCall() || tx->HasOpSpend();
    }
    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > dgpMaxBlockSigOps)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

void ChainstateManager::UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev) const
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != NO_WITNESS_COMMITMENT && DeploymentActiveAfter(pindexPrev, *this, Consensus::DEPLOYMENT_SEGWIT) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> ChainstateManager::GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, bool fProofOfStake) const
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (commitpos == NO_WITNESS_COMMITMENT) {
        uint256 witnessroot = BlockWitnessMerkleRoot(block, nullptr, &fProofOfStake);
        CHash256().Write(witnessroot).Write(ret).Finalize(witnessroot);
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        out.scriptPubKey[0] = OP_RETURN;
        out.scriptPubKey[1] = 0x24;
        out.scriptPubKey[2] = 0xaa;
        out.scriptPubKey[3] = 0x21;
        out.scriptPubKey[4] = 0xa9;
        out.scriptPubKey[5] = 0xed;
        memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
        commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
        CMutableTransaction tx(*block.vtx[0]);
        tx.vout.push_back(out);
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
    UpdateUncommittedBlockStructures(block, pindexPrev);
    return commitment;
}

bool HasValidProofOfWork(const std::vector<CBlockHeader>& headers, const Consensus::Params& consensusParams)
{
    return std::all_of(headers.cbegin(), headers.cend(),
            [&](const auto& header) { return header.IsProofOfStake() ? true : CheckProofOfWork(header.GetHash(), header.nBits, consensusParams);});
}

arith_uint256 CalculateHeadersWork(const std::vector<CBlockHeader>& headers)
{
    arith_uint256 total_work{0};
    for (const CBlockHeader& header : headers) {
        CBlockIndex dummy(header);
        total_work += GetBlockProof(dummy);
    }
    return total_work;
}

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 *  NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, BlockManager& blockman, const ChainstateManager& chainman, const CBlockIndex* pindexPrev, NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work
    const Consensus::Params& consensusParams = chainman.GetConsensus();
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams, block.IsProofOfStake()))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits", "incorrect difficulty value");

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // BlockIndex().
        const CBlockIndex* pcheckpoint = blockman.GetLastCheckpoint(chainman.GetParams().Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight) {
            LogPrintf("ERROR: %s: forked chain older than last checkpoint (height %d)\n", __func__, nHeight);
            return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT, "bad-fork-prior-to-checkpoint");
        }
        if(!blockman.CheckHardened(nHeight, block.GetHash(), chainman.GetParams().Checkpoints())) {
            return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT, "bad-fork-hardened-checkpoint", strprintf("%s: expected hardened checkpoint at height %d", __func__, nHeight));
        }
    }

    // Check that the block satisfies synchronized checkpoint
    if (!blockman.CheckSync(nHeight, chainman.ActiveTip()))
        return state.Invalid(BlockValidationResult::BLOCK_HEADER_SYNC, "bad-fork-prior-to-synch-checkpoint", strprintf("%s: forked chain older than synchronized checkpoint (height %d)", __func__, nHeight));

    // Check timestamp against prev
    if (pindexPrev && block.IsProofOfStake() && block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    int64_t nAdjustedTime = TicksSinceEpoch<std::chrono::seconds>(now);
    if (block.IsProofOfStake() && block.GetBlockTime() > FutureDrift(nAdjustedTime, nHeight, consensusParams)) {
        return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");
    }

    // Reject blocks with outdated version
    if ((block.nVersion < 2 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_HEIGHTINCB)) ||
        (block.nVersion < 3 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_DERSIG)) ||
        (block.nVersion < 4 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_CLTV))) {
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));
    }

    return true;
}

/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock& block, BlockValidationState& state, const ChainstateManager& chainman, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Enforce BIP113 (Median Time Past).
    bool enforce_locktime_median_time_past{false};
    if (DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_CSV)) {
        assert(pindexPrev != nullptr);
        enforce_locktime_median_time_past = true;
    }

    const int64_t nLockTimeCutoff{enforce_locktime_median_time_past ?
                                      pindexPrev->GetMedianTimePast() :
                                      block.GetBlockTime()};

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal", "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_HEIGHTINCB))
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness reserved value (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness reserved value). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_SEGWIT)) {
        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != NO_WITNESS_COMMITMENT) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-nonce-size", strprintf("%s : invalid witness reserved value size", __func__));
            }
            CHash256().Write(hashWitness).Write(block.vtx[0]->vin[0].scriptWitness.stack[0]).Finalize(hashWitness);
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-merkle-match", strprintf("%s : witness merkle commitment mismatch", __func__));
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
      for (const auto& tx : block.vtx) {
            if (tx->HasWitness()) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "unexpected-witness", strprintf("%s : unexpected witness data found", __func__));
            }
        }
    }

    return true;
}

bool Chainstate::UpdateHashProof(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, CBlockIndex* pindex, CCoinsViewCache& view)
{
    int nHeight = pindex->nHeight;
    uint256 hash = block.GetHash();

    //reject proof of work at height consensusParams.nLastPOWBlock
    if (block.IsProofOfWork() && nHeight > consensusParams.nLastPOWBlock)
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "reject-pow", strprintf("UpdateHashProof() : reject proof-of-work at height %d", nHeight));
    
    // Check coinstake timestamp
    if (block.IsProofOfStake() && !CheckCoinStakeTimestamp(block.GetBlockTime(), nHeight, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "timestamp-invalid", strprintf("UpdateHashProof() : coinstake timestamp violation nTimeBlock=%d", block.GetBlockTime()));

    // Check proof-of-work or proof-of-stake
    if (block.nBits != GetNextWorkRequired(pindex->pprev, &block, consensusParams,block.IsProofOfStake()))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits", strprintf("UpdateHashProof() : incorrect %s", block.IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    uint256 hashProof;
    // Verify hash target and signature of coinstake tx
    if (block.IsProofOfStake())
    {
        uint256 targetProofOfStake;
        if (!CheckProofOfStake(pindex->pprev, state, *block.vtx[1], block.nBits, block.nTime, block.GetProofOfDelegation(), block.prevoutStake, hashProof, targetProofOfStake, view, *this))
        {
            return error("UpdateHashProof() : check proof-of-stake failed for block %s", hash.ToString());
        }
    }
    
    // PoW is checked in CheckBlock()
    if (block.IsProofOfWork())
    {
        hashProof = block.GetHash();
    }
    
    // Record proof hash value
    pindex->hashProof = hashProof;
    return true;
}

bool CheckPOS(const CBlockHeader& block, CBlockIndex* pindexPrev, Chainstate& chainstate)
{
    // Determining if PoS is possible to be checked in the header
    int nHeight = pindexPrev->nHeight + 1;
    int coinbaseMaturity = ::Params().GetConsensus().CoinbaseMaturity(nHeight);
    int diff = nHeight - chainstate.m_chain.Height();
    if(pindexPrev && block.IsProofOfStake() && !chainstate.IsInitialBlockDownload()
    // Additional check if not triggered initial block download, like when PoW blocks were initially created
    // CheckPOS is called after ContextualCheckBlockHeader where future block headers are not accepted
            && (diff < coinbaseMaturity))
    {
        // Old header not child of the Tip
        if(diff < -coinbaseMaturity)
            return true;

        // New header
        // Determining if the header is child of the Tip
        CBlockIndex* prev = pindexPrev;
        for(int i = 0; i < coinbaseMaturity; i++)
        {
            if(prev == chainstate.m_chain.Tip())
                return true;
            prev = prev->pprev;
        }
    }

    // PoS header proofs are not validated
    return false;
}

bool ChainstateManager::AcceptBlockHeader(const CBlockHeader& block, BlockValidationState& state, CBlockIndex** ppindex, bool min_pow_checked)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    Chainstate& chainstate = ActiveChainstate();
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf{m_blockman.m_block_index.find(hash)};
    if (hash != GetConsensus().hashGenesisBlock) {
        if (miSelf != m_blockman.m_block_index.end()) {
            // Block header is already known.
            CBlockIndex* pindex = &(miSelf->second);
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                LogPrint(BCLog::VALIDATION, "%s: block %s is marked invalid\n", __func__, hash.ToString());
                return state.Invalid(BlockValidationResult::BLOCK_CACHED_INVALID, "duplicate");
            }
            return true;
        }

        // Check for the checkpoint
        if (chainstate.m_chain.Tip() && block.hashPrevBlock != chainstate.m_chain.Tip()->GetBlockHash())
        {
            // Extra checks to prevent "fill up memory by spamming with bogus blocks"
            const CBlockIndex* pcheckpoint = m_blockman.AutoSelectSyncCheckpoint(chainstate.m_chain.Tip());
            int64_t deltaTime = block.GetBlockTime() - pcheckpoint->nTime;
            if (deltaTime < 0)
            {
                return state.Invalid(BlockValidationResult::BLOCK_HEADER_SYNC, "older-than-checkpoint", "AcceptBlockHeader(): Block with a timestamp before last checkpoint");
            }
        }

        // Check for the signiture encoding
        if (!CheckCanonicalBlockSignature(&block))
        {
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-signature-encoding", "AcceptBlockHeader(): bad block signature encoding");
        }

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi{m_blockman.m_block_index.find(block.hashPrevBlock)};
        if (mi == m_blockman.m_block_index.end()) {
            LogPrint(BCLog::VALIDATION, "%s: %s prev block not found\n", __func__, hash.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "prev-blk-not-found");
        }
        pindexPrev = &((*mi).second);
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK) {
            LogPrint(BCLog::VALIDATION, "%s: %s prev block invalid\n", __func__, hash.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
        }
        if (!ContextualCheckBlockHeader(block, state, m_blockman, *this, pindexPrev, m_options.adjusted_time_callback())) {
            LogPrint(BCLog::VALIDATION, "%s: Consensus::ContextualCheckBlockHeader: %s, %s\n", __func__, hash.ToString(), state.ToString());
            return false;
        }

        /* Determine if this block descends from any block which has been found
         * invalid (m_failed_blocks), then mark pindexPrev and any blocks between
         * them as failed. For example:
         *
         *                D3
         *              /
         *      B2 - C2
         *    /         \
         *  A             D2 - E2 - F2
         *    \
         *      B1 - C1 - D1 - E1
         *
         * In the case that we attempted to reorg from E1 to F2, only to find
         * C2 to be invalid, we would mark D2, E2, and F2 as BLOCK_FAILED_CHILD
         * but NOT D3 (it was not in any of our candidate sets at the time).
         *
         * In any case D3 will also be marked as BLOCK_FAILED_CHILD at restart
         * in LoadBlockIndex.
         */
        if (!pindexPrev->IsValid(BLOCK_VALID_SCRIPTS)) {
            // The above does not mean "invalid": it checks if the previous block
            // hasn't been validated up to BLOCK_VALID_SCRIPTS. This is a performance
            // optimization, in the common case of adding a new block to the tip,
            // we don't need to iterate over the failed blocks list.
            for (const CBlockIndex* failedit : m_failed_blocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    assert(failedit->nStatus & BLOCK_FAILED_VALID);
                    CBlockIndex* invalid_walk = pindexPrev;
                    while (invalid_walk != failedit) {
                        invalid_walk->nStatus |= BLOCK_FAILED_CHILD;
                        m_blockman.m_dirty_blockindex.insert(invalid_walk);
                        invalid_walk = invalid_walk->pprev;
                    }
                    LogPrint(BCLog::VALIDATION, "%s: %s prev block invalid\n", __func__, hash.ToString());
                    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
                }
            }
        }

        // Reject proof of work at height consensusParams.nLastPOWBlock
        int nHeight = pindexPrev->nHeight + 1;
        if (block.IsProofOfWork() && nHeight > GetConsensus().nLastPOWBlock)
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "reject-pow", strprintf("reject proof-of-work at height %d", nHeight));

        if(block.IsProofOfStake())
        {
            // Reject proof of stake before height coinbaseMaturity
            int coinbaseMaturity = GetConsensus().CoinbaseMaturity(nHeight);
            if (nHeight < coinbaseMaturity)
                return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "reject-pos", strprintf("reject proof-of-stake at height %d", nHeight));

            // Check coin stake timestamp
            if(!CheckCoinStakeTimestamp(block.nTime, nHeight, GetConsensus()))
                return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "timestamp-invalid", "proof of stake failed due to invalid timestamp");
        }

        // Check block header
        // if (!CheckBlockHeader(block, state, GetConsensus(), true, CheckPOS(block, pindexPrev)))
        if (!CheckBlockHeader(block, state, GetConsensus(), chainstate)) {
            LogPrint(BCLog::VALIDATION, "%s: Consensus::CheckBlockHeader: %s, %s\n", __func__, hash.ToString(), state.ToString());
            return false;
        }
    }
    if (!min_pow_checked) {
        LogPrint(BCLog::VALIDATION, "%s: not adding new block header %s, missing anti-dos proof-of-work validation\n", __func__, hash.ToString());
        return state.Invalid(BlockValidationResult::BLOCK_HEADER_LOW_WORK, "too-little-chainwork");
    }
    CBlockIndex* pindex{m_blockman.AddToBlockIndex(block, m_best_header)};

    if (ppindex)
        *ppindex = pindex;

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ChainstateManager::ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, bool min_pow_checked, BlockValidationState& state, const CBlockIndex** ppindex,  const CBlockIndex** pindexFirst)
{
    if(!ActiveChainstate().IsInitialBlockDownload() && headers.size() > 1) {
        LOCK(cs_main);
        const CBlockHeader last_header = headers[headers.size()-1];
        unsigned int nHeight = ActiveChain().Height() + 1;
        if (last_header.IsProofOfStake() && last_header.GetBlockTime() > FutureDrift(GetAdjustedTimeSeconds(), nHeight, GetConsensus())) {
            return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");
        }
    }
    AssertLockNotHeld(cs_main);
    {
        LOCK(cs_main);
        bool bFirst = true;
        bool fInstantBan = false;
        for (size_t i = 0; i < headers.size(); ++i) {
            const CBlockHeader& header = headers[i];

            // If the stake has been seen and the header has not yet been seen
            if (!fReindex && !fImporting && !ActiveChainstate().IsInitialBlockDownload() && header.IsProofOfStake() && setStakeSeen.count(std::make_pair(header.prevoutStake, header.nTime)) && !BlockIndex().count(header.GetHash())) {
                // if it is the last header of the list
                if(i+1 == headers.size()) {
                    if(fInstantBan) {
                        // if we've seen a dupe stake header already in this list, then instaban
                        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "dupe-stake", strprintf("%s: duplicate proof-of-stake instant ban (%s, %d) for header %s", __func__, header.prevoutStake.ToString(), header.nTime, header.GetHash().ToString()));
                    } else {
                        // otherwise just reject the block until it is part of a longer list
                        return state.Invalid(BlockValidationResult::BLOCK_HEADER_REJECT, "dupe-stake", strprintf("%s: duplicate proof-of-stake (%s, %d) for header %s", __func__, header.prevoutStake.ToString(), header.nTime, header.GetHash().ToString()));
                    }
                } else {
                    // if it is not part of the longest chain, then any error on a subsequent header should result in an instant ban
                    fInstantBan = true;
                }
            }
            CBlockIndex *pindex = nullptr; // Use a temp pindex instead of ppindex to avoid a const_cast
            bool accepted{AcceptBlockHeader(header, state, &pindex, min_pow_checked)};
            ActiveChainstate().CheckBlockIndex();

            if (!accepted) {
                // if we have seen a duplicate stake in this header list previously, then ban immediately.
                if(fInstantBan) {
                    state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, state.GetRejectReason(), "instant ban, due to duplicate header in the chain");
                }
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
                if(bFirst && pindexFirst)
                {
                    *pindexFirst = pindex;
                    bFirst = false;
                }
            }
        }
    }
    if (NotifyHeaderTip(ActiveChainstate())) {
        if (ActiveChainstate().IsInitialBlockDownload() && ppindex && *ppindex) {
            const CBlockIndex& last_accepted{**ppindex};
            const int64_t blocks_left{(GetTime() - last_accepted.GetBlockTime()) / GetConsensus().TargetSpacing(last_accepted.nHeight)};
            const double progress{100.0 * last_accepted.nHeight / (last_accepted.nHeight + blocks_left)};
            LogPrintf("Synchronizing blockheaders, height: %d (~%.2f%%)\n", last_accepted.nHeight, progress);
        }
    }
    return true;
}

void ChainstateManager::ReportHeadersPresync(const arith_uint256& work, int64_t height, int64_t timestamp)
{
    AssertLockNotHeld(cs_main);
    const auto& chainstate = ActiveChainstate();
    {
        LOCK(cs_main);
        // Don't report headers presync progress if we already have a post-minchainwork header chain.
        // This means we lose reporting for potentially legitimate, but unlikely, deep reorgs, but
        // prevent attackers that spam low-work headers from filling our logs.
        if (m_best_header->nChainWork >= UintToArith256(GetConsensus().nMinimumChainWork)) return;
        // Rate limit headers presync updates to 4 per second, as these are not subject to DoS
        // protection.
        auto now = std::chrono::steady_clock::now();
        if (now < m_last_presync_update + std::chrono::milliseconds{250}) return;
        m_last_presync_update = now;
    }
    bool initial_download = chainstate.IsInitialBlockDownload();
    uiInterface.NotifyHeaderTip(GetSynchronizationState(initial_download), height, timestamp, /*presync=*/true);
    if (initial_download) {
        const int64_t blocks_left{(GetTime() - timestamp) / GetConsensus().nPowTargetSpacing};
        const double progress{100.0 * height / (height + blocks_left)};
        LogPrintf("Pre-synchronizing blockheaders, height: %d (~%.2f%%)\n", height, progress);
    }
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool Chainstate::AcceptBlock(const std::shared_ptr<const CBlock>& pblock, BlockValidationState& state, CBlockIndex** ppindex, bool fRequested, const FlatFilePos* dbp, bool* fNewBlock, bool min_pow_checked)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDummy = nullptr;
    CBlockIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    bool accepted_header{m_chainman.AcceptBlockHeader(block, state, &pindex, min_pow_checked)};
    CheckBlockIndex();

    if (!accepted_header)
        return false;

    if(block.IsProofOfWork()) {
        if (!UpdateHashProof(block, state, m_params.GetConsensus(), pindex, CoinsTip()))
        {
            return error("%s: AcceptBlock(): %s", __func__, state.GetRejectReason().c_str());
        }
    }

    // Get prev block index
    CBlockIndex* pindexPrev = nullptr;
    if(pindex->nHeight > 0){
        BlockMap::iterator mi = m_blockman.m_block_index.find(block.hashPrevBlock);
        if (mi == m_blockman.m_block_index.end())
            return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "prev-blk-not-found", strprintf("%s: prev block not found", __func__));
        pindexPrev = &((*mi).second);
    }

    // Get block height
    int nHeight = pindex->nHeight;

    // Check for the last proof of work block
    if (block.IsProofOfWork() && nHeight > m_params.GetConsensus().nLastPOWBlock)
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "reject-pow", strprintf("%s: reject proof-of-work at height %d", __func__, nHeight));

    // Check that the block satisfies synchronized checkpoint
    if (!m_blockman.CheckSync(nHeight, m_chain.Tip()))
        return error("AcceptBlock() : rejected by synchronized checkpoint");

    // Check timestamp against prev
    if (pindexPrev && block.IsProofOfStake() && (block.GetBlockTime() <= pindexPrev->GetBlockTime() || FutureDrift(block.GetBlockTime(), nHeight, m_params.GetConsensus()) < pindexPrev->GetBlockTime()))
        return error("AcceptBlock() : block's timestamp is too early");

    // Check timestamp
    if (block.IsProofOfStake() &&  block.GetBlockTime() > FutureDrift(GetAdjustedTimeSeconds(), nHeight, m_params.GetConsensus()))
        return error("AcceptBlock() : block timestamp too far in the future");

    // Enforce rule that the coinbase starts with serialized block height
    if (nHeight >= m_params.GetConsensus().BIP34Height)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin()))
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
    }

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreWork = (m_chain.Tip() ? pindex->nChainWork > m_chain.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead{pindex->nHeight > m_chain.Height() + int(MIN_BLOCKS_TO_KEEP)};

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.
    // Note that this would break the getblockfrompeer RPC

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;    // This is a previously-processed block that was pruned
        if (!fHasMoreWork) return true; // Don't process less-work OR equal-work chains
        if (fTooFarAhead) return true;        // Block height is too high

        // Protect against DoS attacks from low-work chains.
        // If our tip is behind, a peer could try to send us
        // low-work blocks on a fake chain that we would never
        // request; don't process these.
        if (pindex->nChainWork < nMinimumChainWork) return true;
    }

    if (!CheckBlock(block, state, m_params.GetConsensus(), *this) ||
        !ContextualCheckBlock(block, state, m_chainman, pindex->pprev)) {
        if (state.IsInvalid() && state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            m_blockman.m_dirty_blockindex.insert(pindex);
        }
        return error("%s: %s", __func__, state.ToString());
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)

    // Write block to history file
    if (fNewBlock) *fNewBlock = true;
    try {
        FlatFilePos blockPos{m_blockman.SaveBlockToDisk(block, pindex->nHeight, m_chain, m_params, dbp)};
        if (blockPos.IsNull()) {
            state.Error(strprintf("%s: Failed to find position to write new block to disk", __func__));
            return false;
        }
        ReceivedBlockTransactions(block, pindex, blockPos);
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    FlushStateToDisk(state, FlushStateMode::NONE);

    CheckBlockIndex();

    return true;
}

bool IsCanonicalBlockSignature(const CBlockHeader* pblock, bool checkLowS)
{
    if (pblock->IsProofOfWork()) {
        return pblock->vchBlockSigDlgt.empty();
    }

    return checkLowS ? IsLowDERSignature(pblock->vchBlockSigDlgt, NULL, false) : IsDERSignature(pblock->vchBlockSigDlgt, NULL, false);
}

bool CheckCanonicalBlockSignature(const CBlockHeader* pblock)
{
    // Check compact signature size
    if(pblock->IsProofOfStake() && pblock->GetBlockSignature().size() == CPubKey::COMPACT_SIGNATURE_SIZE)
        return pblock->HasProofOfDelegation() ? pblock->GetProofOfDelegation().size() == CPubKey::COMPACT_SIGNATURE_SIZE : true;

    //block signature encoding
    bool ret = IsCanonicalBlockSignature(pblock, false);

    //block signature encoding (low-s)
    if(ret) ret = IsCanonicalBlockSignature(pblock, true);

    return ret;
}

bool ChainstateManager::ProcessNewBlock(const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked, bool* new_block)
{
    AssertLockNotHeld(cs_main);

    {
        CBlockIndex *pindex = nullptr;
        if (new_block) *new_block = false;
        BlockValidationState state;

        // CheckBlock() does not support multi-threaded block validation because CBlock::fChecked can cause data race.
        // Therefore, the following critical section must include the CheckBlock() call as well.
        LOCK(cs_main);

        // Skipping AcceptBlock() for CheckBlock() failures means that we will never mark a block as invalid if
        // CheckBlock() fails.  This is protective against consensus failure if there are any unknown forms of block
        // malleability that cause CheckBlock() to fail; see e.g. CVE-2012-2459 and
        // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-February/016697.html.  Because CheckBlock() is
        // not very expensive, the anti-DoS benefits of caching failure (of a definitely-invalid block) are not substantial.
        bool ret = CheckBlock(*block, state, GetConsensus(), ActiveChainstate());
        if (ret) {
            // Store to disk
            ret = ActiveChainstate().AcceptBlock(block, state, &pindex, force_processing, nullptr, new_block, min_pow_checked);
        }
        if (!ret) {
            GetMainSignals().BlockChecked(*block, state);
            return error("%s: AcceptBlock FAILED (%s)", __func__, state.ToString());
        }
    }

    NotifyHeaderTip(ActiveChainstate());

    BlockValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!ActiveChainstate().ActivateBestChain(state, block)) {
        return error("%s: ActivateBestChain failed (%s)", __func__, state.ToString());
    }

    return true;
}

MempoolAcceptResult ChainstateManager::ProcessTransaction(const CTransactionRef& tx, bool test_accept)
{
    AssertLockHeld(cs_main);
    Chainstate& active_chainstate = ActiveChainstate();
    if (!active_chainstate.GetMempool()) {
        TxValidationState state;
        state.Invalid(TxValidationResult::TX_NO_MEMPOOL, "no-mempool");
        return MempoolAcceptResult::Failure(state);
    }
    auto result = AcceptToMemoryPool(active_chainstate, tx, GetTime(), /*bypass_limits=*/ false, test_accept);
    active_chainstate.GetMempool()->check(active_chainstate.CoinsTip(), active_chainstate.m_chain.Height() + 1);
    return result;
}

bool TestBlockValidity(BlockValidationState& state,
                       const CChainParams& chainparams,
                       Chainstate& chainstate,
                       const CBlock& block,
                       CBlockIndex* pindexPrev,
                       const std::function<NodeClock::time_point()>& adjusted_time_callback,
                       bool fCheckPOW,
                       bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainstate.m_chain.Tip());
    CCoinsViewCache viewNew(&chainstate.CoinsTip());
    uint256 block_hash(block.GetHash());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;
    indexDummy.phashBlock = &block_hash;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainstate.m_blockman, chainstate.m_chainman, pindexPrev, adjusted_time_callback()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, state.ToString());
    if (!CheckBlock(block, state, chainparams.GetConsensus(), chainstate, fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    if (!ContextualCheckBlock(block, state, chainstate.m_chainman, pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, state.ToString());

    dev::h256 oldHashStateRoot(globalState->rootHash()); // runebase
    dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // runebase

    if (!chainstate.ConnectBlock(block, state, &indexDummy, viewNew, true)) {
        globalState->setRoot(oldHashStateRoot); // runebase
        globalState->setRootUTXO(oldHashUTXORoot); // runebase
        pstorageresult->clearCacheResult();
        return false;
    }
    assert(state.IsValid());

    return true;
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(Chainstate& active_chainstate, int nManualPruneHeight)
{
    BlockValidationState state;
    if (!active_chainstate.FlushStateToDisk(
            state, FlushStateMode::NONE, nManualPruneHeight)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

void Chainstate::LoadMempool(const fs::path& load_path, FopenFn mockable_fopen_function)
{
    if (!m_mempool) return;
    ::LoadMempool(*m_mempool, load_path, *this, mockable_fopen_function);
    m_mempool->SetLoadTried(!ShutdownRequested());
}

bool Chainstate::LoadChainTip()
{
    AssertLockHeld(cs_main);
    const CCoinsViewCache& coins_cache = CoinsTip();
    assert(!coins_cache.GetBestBlock().IsNull()); // Never called when the coins view is empty
    const CBlockIndex* tip = m_chain.Tip();

    if (tip && tip->GetBlockHash() == coins_cache.GetBestBlock()) {
        return true;
    }

    // Load pointer to end of best chain
    CBlockIndex* pindex = m_blockman.LookupBlockIndex(coins_cache.GetBestBlock());
    if (!pindex) {
        return false;
    }
    m_chain.SetTip(*pindex);
    PruneBlockIndexCandidates();

    tip = m_chain.Tip();
    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
              tip->GetBlockHash().ToString(),
              m_chain.Height(),
              FormatISO8601DateTime(tip->GetBlockTime()),
              GuessVerificationProgress(m_params.TxData(), tip));
    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks…").translated, 0, false);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100, false);
}

bool CVerifyDB::VerifyDB(
    Chainstate& chainstate,
    const Consensus::Params& consensus_params,
    CCoinsView& coinsview,
    int nCheckLevel, int nCheckDepth)
{
    AssertLockHeld(cs_main);

    if (chainstate.m_chain.Tip() == nullptr || chainstate.m_chain.Tip()->pprev == nullptr) {
        return true;
    }

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainstate.m_chain.Height()) {
        nCheckDepth = chainstate.m_chain.Height();
    }
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(&coinsview);
    CBlockIndex* pindex;
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    BlockValidationState state;
    int reportDone = 0;

////////////////////////////////////////////////////////////////////////// // runebase
    dev::h256 oldHashStateRoot(globalState->rootHash());
    dev::h256 oldHashUTXORoot(globalState->rootHashUTXO());
    RunebaseDGP runebaseDGP(globalState.get(), chainstate, fGettingValuesDGP);
//////////////////////////////////////////////////////////////////////////

    LogPrintf("[0%%]..."); /* Continued */

    const bool is_snapshot_cs{!chainstate.m_from_snapshot_blockhash};

    for (pindex = chainstate.m_chain.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        const int percentageDone = std::max(1, std::min(99, (int)(((double)(chainstate.m_chain.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone / 10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone); /* Continued */
            reportDone = percentageDone / 10;
        }
        uiInterface.ShowProgress(_("Verifying blocks…").translated, percentageDone, false);
        if (pindex->nHeight <= chainstate.m_chain.Height() - nCheckDepth) {
            break;
        }
        if ((fPruneMode || is_snapshot_cs) && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning or running under an assumeutxo snapshot, only go
            // back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }

        ///////////////////////////////////////////////////////////////////// // runebase
        uint32_t sizeBlockDGP = runebaseDGP.getBlockSize(pindex->nHeight);
        dgpMaxBlockSize = sizeBlockDGP ? sizeBlockDGP : dgpMaxBlockSize;
        updateBlockSizeParams(dgpMaxBlockSize);
        /////////////////////////////////////////////////////////////////////

        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, consensus_params)) {
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        }
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, consensus_params, chainstate,false)) {
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
        }
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!UndoReadFromDisk(undo, pindex)) {
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        size_t curr_coins_usage = coins.DynamicMemoryUsage() + chainstate.CoinsTip().DynamicMemoryUsage();

        if (nCheckLevel >= 3 && curr_coins_usage <= chainstate.m_coinstip_cache_size_bytes) {
            assert(coins.GetBestBlock() == pindex->GetBlockHash());
            bool fClean=true;
            DisconnectResult res = chainstate.DisconnectBlock(block, pindex, coins, &fClean);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested()) return true;
    }
    if (pindexFailure) {
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainstate.m_chain.Height() - pindexFailure->nHeight + 1, nGoodTransactions);
    }

    // store block count as we move pindex at check level >= 4
    int block_count = chainstate.m_chain.Height() - pindex->nHeight;

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        while (pindex != chainstate.m_chain.Tip()) {
            const int percentageDone = std::max(1, std::min(99, 100 - (int)(((double)(chainstate.m_chain.Height() - pindex->nHeight)) / (double)nCheckDepth * 50)));
            if (reportDone < percentageDone / 10) {
                // report every 10% step
                LogPrintf("[%d%%]...", percentageDone); /* Continued */
                reportDone = percentageDone / 10;
            }
            uiInterface.ShowProgress(_("Verifying blocks…").translated, percentageDone, false);
            pindex = chainstate.m_chain.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, consensus_params))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());

            dev::h256 oldHashStateRoot(globalState->rootHash()); // runebase
            dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // runebase

            if (!chainstate.ConnectBlock(block, state, pindex, coins)) {
                globalState->setRoot(oldHashStateRoot); // runebase
                globalState->setRootUTXO(oldHashUTXORoot); // runebase
                pstorageresult->clearCacheResult();
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s (%s)", pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
            }
            if (ShutdownRequested()) return true;
        }
    } else {
        globalState->setRoot(oldHashStateRoot); // runebase
        globalState->setRootUTXO(oldHashUTXORoot); // runebase
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", block_count, nGoodTransactions);

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
bool Chainstate::RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs)
{
    AssertLockHeld(cs_main);
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, m_params.GetConsensus())) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn &txin : tx->vin) {
                inputs.SpendCoin(txin.prevout);
            }
        }
        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, true);
    }
    return true;
}

bool Chainstate::ReplayBlocks()
{
    LOCK(cs_main);

    CCoinsView& db = this->CoinsDB();
    CCoinsViewCache cache(&db);

    std::vector<uint256> hashHeads = db.GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("ReplayBlocks(): unknown inconsistent state");

    uiInterface.ShowProgress(_("Replaying blocks…").translated, 0, false);
    LogPrintf("Replaying blocks\n");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    if (m_blockman.m_block_index.count(hashHeads[0]) == 0) {
        return error("ReplayBlocks(): reorganization to unknown block requested");
    }
    pindexNew = &(m_blockman.m_block_index[hashHeads[0]]);

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (m_blockman.m_block_index.count(hashHeads[1]) == 0) {
            return error("ReplayBlocks(): reorganization from unknown block requested");
        }
        pindexOld = &(m_blockman.m_block_index[hashHeads[1]]);
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
            CBlock block;
            if (!ReadBlockFromDisk(block, pindexOld, m_params.GetConsensus())) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            LogPrintf("Rolling back %s (%i)\n", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
            bool fClean=true;
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache, &fClean);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
        const CBlockIndex& pindex{*Assert(pindexNew->GetAncestor(nHeight))};

        LogPrintf("Rolling forward %s (%i)\n", pindex.GetBlockHash().ToString(), nHeight);
        uiInterface.ShowProgress(_("Replaying blocks…").translated, (int) ((nHeight - nForkHeight) * 100.0 / (pindexNew->nHeight - nForkHeight)) , false);
        if (!RollforwardBlock(&pindex, cache)) return false;
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    cache.Flush();
    uiInterface.ShowProgress("", 100, false);
    return true;
}

bool Chainstate::NeedsRedownload() const
{
    AssertLockHeld(cs_main);

    // At and above m_params.SegwitHeight, segwit consensus rules must be validated
    CBlockIndex* block{m_chain.Tip()};

    while (block != nullptr && DeploymentActiveAt(*block, m_chainman, Consensus::DEPLOYMENT_SEGWIT)) {
        if (!(block->nStatus & BLOCK_OPT_WITNESS)) {
            // block is insufficiently validated for a segwit client
            return true;
        }
        block = block->pprev;
    }

    return false;
}

void Chainstate::UnloadBlockIndex()
{
    AssertLockHeld(::cs_main);
    nBlockSequenceId = 1;
    setBlockIndexCandidates.clear();
}

bool ChainstateManager::LoadBlockIndex()
{
    AssertLockHeld(cs_main);
    // Load block index from databases
    bool needs_init = fReindex;
    if (!fReindex) {
        bool ret = m_blockman.LoadBlockIndexDB(GetConsensus());
        if (!ret) return false;

        std::vector<CBlockIndex*> vSortedByHeight{m_blockman.GetAllBlockIndices()};
        std::sort(vSortedByHeight.begin(), vSortedByHeight.end(),
                  CBlockIndexHeightOnlyComparator());

        // Find start of assumed-valid region.
        int first_assumed_valid_height = std::numeric_limits<int>::max();

        for (const CBlockIndex* block : vSortedByHeight) {
            if (block->IsAssumedValid()) {
                auto chainstates = GetAll();

                // If we encounter an assumed-valid block index entry, ensure that we have
                // one chainstate that tolerates assumed-valid entries and another that does
                // not (i.e. the background validation chainstate), since assumed-valid
                // entries should always be pending validation by a fully-validated chainstate.
                auto any_chain = [&](auto fnc) { return std::any_of(chainstates.cbegin(), chainstates.cend(), fnc); };
                assert(any_chain([](auto chainstate) { return chainstate->reliesOnAssumedValid(); }));
                assert(any_chain([](auto chainstate) { return !chainstate->reliesOnAssumedValid(); }));

                first_assumed_valid_height = block->nHeight;
                break;
            }
        }

        for (CBlockIndex* pindex : vSortedByHeight) {
            if (ShutdownRequested()) return false;
            if (pindex->IsAssumedValid() ||
                    (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) &&
                     (pindex->HaveTxsDownloaded() || pindex->pprev == nullptr))) {

                // Fill each chainstate's block candidate set. Only add assumed-valid
                // blocks to the tip candidate set if the chainstate is allowed to rely on
                // assumed-valid blocks.
                //
                // If all setBlockIndexCandidates contained the assumed-valid blocks, the
                // background chainstate's ActivateBestChain() call would add assumed-valid
                // blocks to the chain (based on how FindMostWorkChain() works). Obviously
                // we don't want this since the purpose of the background validation chain
                // is to validate assued-valid blocks.
                //
                // Note: This is considering all blocks whose height is greater or equal to
                // the first assumed-valid block to be assumed-valid blocks, and excluding
                // them from the background chainstate's setBlockIndexCandidates set. This
                // does mean that some blocks which are not technically assumed-valid
                // (later blocks on a fork beginning before the first assumed-valid block)
                // might not get added to the background chainstate, but this is ok,
                // because they will still be attached to the active chainstate if they
                // actually contain more work.
                //
                // Instead of this height-based approach, an earlier attempt was made at
                // detecting "holistically" whether the block index under consideration
                // relied on an assumed-valid ancestor, but this proved to be too slow to
                // be practical.
                for (Chainstate* chainstate : GetAll()) {
                    if (chainstate->reliesOnAssumedValid() ||
                            pindex->nHeight < first_assumed_valid_height) {
                        chainstate->setBlockIndexCandidates.insert(pindex);
                    }
                }
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK && (!m_best_invalid || pindex->nChainWork > m_best_invalid->nChainWork)) {
                m_best_invalid = pindex;
            }
            if (pindex->IsValid(BLOCK_VALID_TREE) && (m_best_header == nullptr || CBlockIndexWorkComparator()(m_best_header, pindex)))
                m_best_header = pindex;
        }

        needs_init = m_blockman.m_block_index.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
        // Use the provided setting for -logevents in the new database
        fLogEvents = gArgs.GetBoolArg("-logevents", DEFAULT_LOGEVENTS);
        m_blockman.m_block_tree_db->WriteFlag("logevents", fLogEvents);
        /////////////////////////////////////////////////////////////// // runebase
        fAddressIndex = gArgs.GetBoolArg("-addrindex", DEFAULT_ADDRINDEX);
        m_blockman.m_block_tree_db->WriteFlag("addrindex", fAddressIndex);
        ///////////////////////////////////////////////////////////////
    }
    return true;
}

bool Chainstate::LoadGenesisBlock()
{
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // m_blockman.m_block_index. Note that we can't use m_chain here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (m_blockman.m_block_index.count(m_params.GenesisBlock().GetHash()))
        return true;

    try {
        const CBlock& block = m_params.GenesisBlock();
        FlatFilePos blockPos{m_blockman.SaveBlockToDisk(block, 0, m_chain, m_params, nullptr)};
        if (blockPos.IsNull()) {
            return error("%s: writing genesis block to disk failed", __func__);
        }
        CBlockIndex* pindex = m_blockman.AddToBlockIndex(block, m_chainman.m_best_header);
        pindex->hashProof = m_params.GetConsensus().hashGenesisBlock;
        ReceivedBlockTransactions(block, pindex, blockPos);
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

void Chainstate::LoadExternalBlockFile(
    FILE* fileIn,
    FlatFilePos* dbp,
    std::multimap<uint256, FlatFilePos>* blocks_with_unknown_parent)
{
    AssertLockNotHeld(m_chainstate_mutex);

    // Either both should be specified (-reindex), or neither (-loadblock).
    assert(!dbp == !blocks_with_unknown_parent);

    const auto start{SteadyClock::now()};

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*dgpMaxBlockSerSize, dgpMaxBlockSerSize+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            if (ShutdownRequested()) return;

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(m_params.MessageStart()[0]);
                nRewind = blkdat.GetPos() + 1;
                blkdat >> buf;
                if (memcmp(buf, m_params.MessageStart(), CMessageHeader::MESSAGE_START_SIZE)) {
                    continue;
                }
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > dgpMaxBlockSerSize)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                uint256 hash = block.GetHash();
                {
                    LOCK(cs_main);
                    // detect out of order blocks, and store them for later
                    if (hash != m_params.GetConsensus().hashGenesisBlock && !m_blockman.LookupBlockIndex(block.hashPrevBlock)) {
                        LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                                block.hashPrevBlock.ToString());
                        if (dbp && blocks_with_unknown_parent) {
                            blocks_with_unknown_parent->emplace(block.hashPrevBlock, *dbp);
                        }
                        continue;
                    }

                    // process in case the block isn't known yet
                    const CBlockIndex* pindex = m_blockman.LookupBlockIndex(hash);
                    if (!pindex || (pindex->nStatus & BLOCK_HAVE_DATA) == 0) {
                      BlockValidationState state;
                      if (AcceptBlock(pblock, state, nullptr, true, dbp, nullptr, true)) {
                          nLoaded++;
                      }
                      if (state.IsError()) {
                          break;
                      }
                    } else if (hash != m_params.GetConsensus().hashGenesisBlock && pindex->nHeight % 1000 == 0) {
                        LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), pindex->nHeight);
                    }
                }

                // In Bitcoin this only needed to be done for genesis and at the end of block indexing
                // But for Runebase PoS we need to sync this after every block to ensure txdb is populated for
                // validating PoS proofs
                {
                    BlockValidationState state;
                    if (!ActivateBestChain(state, nullptr)) {
                        break;
                    }
                }

                NotifyHeaderTip(*this);

                if (!blocks_with_unknown_parent) continue;

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    auto range = blocks_with_unknown_parent->equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, FlatFilePos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, m_params.GetConsensus())) {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            BlockValidationState dummy;
                            if (AcceptBlock(pblockrecursive, dummy, nullptr, true, &it->second, nullptr, true)) {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        blocks_with_unknown_parent->erase(it);
                        NotifyHeaderTip(*this);
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));
}

void Chainstate::CheckBlockIndex()
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in m_blockman.m_block_index but no active chain. (A few of the
    // tests when iterating the block tree require that m_chain has been initialized.)
    if (m_chain.Height() < 0) {
        assert(m_blockman.m_block_index.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (auto& [_, block_index] : m_blockman.m_block_index) {
        forward.emplace(block_index.pprev, &block_index);
    }

    assert(forward.size() == m_blockman.m_block_index.size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = nullptr; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        // Assumed-valid index entries will not have data since we haven't downloaded the
        // full block yet.
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA) && !pindex->IsAssumedValid()) {
            pindexFirstMissing = pindex;
        }
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;

        if (pindex->pprev != nullptr && !pindex->IsAssumedValid()) {
            // Skip validity flag checks for BLOCK_ASSUMED_VALID index entries, since these
            // *_VALID_MASK flags will not be present for index entries we are temporarily assuming
            // valid.
            if (pindexFirstNotTransactionsValid == nullptr &&
                    (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) {
                pindexFirstNotTransactionsValid = pindex;
            }

            if (pindexFirstNotChainValid == nullptr &&
                    (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) {
                pindexFirstNotChainValid = pindex;
            }

            if (pindexFirstNotScriptsValid == nullptr &&
                    (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) {
                pindexFirstNotScriptsValid = pindex;
            }
        }

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == m_params.GetConsensus().hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == m_chain.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (!pindex->HaveTxsDownloaded()) assert(pindex->nSequenceId <= 0); // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        // Unless these indexes are assumed valid and pending block download on a
        // background chainstate.
        if (!m_blockman.m_have_pruned && !pindex->IsAssumedValid()) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        if (pindex->IsAssumedValid()) {
            // Assumed-valid blocks should have some nTx value.
            assert(pindex->nTx > 0);
            // Assumed-valid blocks should connect to the main chain.
            assert((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE);
        } else {
            // Otherwise there should only be an nTx value if we have
            // actually seen a block's transactions.
            assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        }
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to HaveTxsDownloaded().
        assert((pindexFirstNeverProcessed == nullptr) == pindex->HaveTxsDownloaded());
        assert((pindexFirstNotTransactionsValid == nullptr) == pindex->HaveTxsDownloaded());
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == nullptr || pindex->nChainWork >= pindex->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr); // All m_blockman.m_block_index entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) && pindexFirstNeverProcessed == nullptr) {
            if (pindexFirstInvalid == nullptr) {
                const bool is_active = this == &m_chainman.ActiveChainstate();

                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  m_chain.Tip() must also be there
                // even if some data has been pruned.
                //
                // Don't perform this check for the background chainstate since
                // its setBlockIndexCandidates shouldn't have some entries (i.e. those past the
                // snapshot block) which do exist in the block index for the active chainstate.
                if (is_active && (pindexFirstMissing == nullptr || pindex == m_chain.Tip())) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in m_blocks_unlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in m_blocks_unlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = m_blockman.m_blocks_unlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != nullptr && pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in m_blocks_unlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in m_blocks_unlinked if we don't HAVE_DATA
        if (pindexFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in m_blocks_unlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == nullptr && pindexFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(m_blockman.m_have_pruned); // We must have pruned.
            // This block may have entered m_blocks_unlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between m_chain and the
            //    tip.
            // So if this block is itself better than m_chain.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in m_blocks_unlinked.
            if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == nullptr) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string Chainstate::ToString()
{
    AssertLockHeld(::cs_main);
    CBlockIndex* tip = m_chain.Tip();
    return strprintf("Chainstate [%s] @ height %d (%s)",
                     m_from_snapshot_blockhash ? "snapshot" : "ibd",
                     tip ? tip->nHeight : -1, tip ? tip->GetBlockHash().ToString() : "null");
}

bool Chainstate::ResizeCoinsCaches(size_t coinstip_size, size_t coinsdb_size)
{
    AssertLockHeld(::cs_main);
    if (coinstip_size == m_coinstip_cache_size_bytes &&
            coinsdb_size == m_coinsdb_cache_size_bytes) {
        // Cache sizes are unchanged, no need to continue.
        return true;
    }
    size_t old_coinstip_size = m_coinstip_cache_size_bytes;
    m_coinstip_cache_size_bytes = coinstip_size;
    m_coinsdb_cache_size_bytes = coinsdb_size;
    CoinsDB().ResizeCache(coinsdb_size);

    LogPrintf("[%s] resized coinsdb cache to %.1f MiB\n",
        this->ToString(), coinsdb_size * (1.0 / 1024 / 1024));
    LogPrintf("[%s] resized coinstip cache to %.1f MiB\n",
        this->ToString(), coinstip_size * (1.0 / 1024 / 1024));

    BlockValidationState state;
    bool ret;

    if (coinstip_size > old_coinstip_size) {
        // Likely no need to flush if cache sizes have grown.
        ret = FlushStateToDisk(state, FlushStateMode::IF_NEEDED);
    } else {
        // Otherwise, flush state to disk and deallocate the in-memory coins map.
        ret = FlushStateToDisk(state, FlushStateMode::ALWAYS);
        CoinsTip().ReallocateCache();
    }
    return ret;
}

bool Chainstate::RemoveBlockIndex(CBlockIndex *pindex)
{
    AssertLockHeld(cs_main);
    // Check if the block index is present in any variable and remove it
    if(m_chainman.m_best_invalid == pindex)
        m_chainman.m_best_invalid = nullptr;

    if(m_chainman.m_best_header == pindex)
        m_chainman.m_best_header = nullptr;

    // Check if the block index is present in any list and remove it
    for (auto it=m_blockman.m_blocks_unlinked.begin(); it!=m_blockman.m_blocks_unlinked.end();){
        if(it->first == pindex || it->second == pindex)
        {
            it = m_blockman.m_blocks_unlinked.erase(it);
        }
        else{
            it++;
        }
    }

    setBlockIndexCandidates.erase(pindex);

    m_chainman.m_failed_blocks.erase(pindex);

    m_blockman.m_dirty_blockindex.erase(pindex);

    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].erase(pindex);
    }

    m_chainman.m_versionbitscache.Erase(pindex);

    return true;
}

//! Guess how far we are in the verification process at the given block index
//! require cs_main if pindex has not been validated yet (because nChainTx might be unset)
double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex *pindex) {
    if (pindex == nullptr)
        return 0.0;

    int64_t nNow = time(nullptr);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return std::min<double>(pindex->nChainTx / fTxTotal, 1.0);
}

std::string exceptedMessage(const dev::eth::TransactionException& excepted, const dev::bytes& output)
{
    std::string message;
    try
    {
        // Process the revert message from the output
        if(excepted == dev::eth::TransactionException::RevertInstruction)
        {
            // Get function: Error(string)
            dev::bytesConstRef oRawData(&output);
            dev::bytes errorFunc = oRawData.cropped(0, 4).toBytes();
            if(dev::toHex(errorFunc) == "08c379a0")
            {
                dev::bytesConstRef oData = oRawData.cropped(4);
                message = dev::eth::ABIDeserialiser<std::string>::deserialise(oData);
            }
        }
    }
    catch(...)
    {}

    return message;
}

std::optional<uint256> ChainstateManager::SnapshotBlockhash() const
{
    LOCK(::cs_main);
    if (m_active_chainstate && m_active_chainstate->m_from_snapshot_blockhash) {
        // If a snapshot chainstate exists, it will always be our active.
        return m_active_chainstate->m_from_snapshot_blockhash;
    }
    return std::nullopt;
}

std::vector<Chainstate*> ChainstateManager::GetAll()
{
    LOCK(::cs_main);
    std::vector<Chainstate*> out;

    if (!IsSnapshotValidated() && m_ibd_chainstate) {
        out.push_back(m_ibd_chainstate.get());
    }

    if (m_snapshot_chainstate) {
        out.push_back(m_snapshot_chainstate.get());
    }

    return out;
}

Chainstate& ChainstateManager::InitializeChainstate(
    CTxMemPool* mempool, const std::optional<uint256>& snapshot_blockhash)
{
    AssertLockHeld(::cs_main);
    bool is_snapshot = snapshot_blockhash.has_value();
    std::unique_ptr<Chainstate>& to_modify =
        is_snapshot ? m_snapshot_chainstate : m_ibd_chainstate;

    if (to_modify) {
        throw std::logic_error("should not be overwriting a chainstate");
    }
    to_modify.reset(new Chainstate(mempool, m_blockman, *this, snapshot_blockhash));

    // Snapshot chainstates and initial IBD chaintates always become active.
    if (is_snapshot || (!is_snapshot && !m_active_chainstate)) {
        LogPrintf("Switching active chainstate to %s\n", to_modify->ToString());
        m_active_chainstate = to_modify.get();
    } else {
        throw std::logic_error("unexpected chainstate activation");
    }

    return *to_modify;
}

const AssumeutxoData* ExpectedAssumeutxo(
    const int height, const CChainParams& chainparams)
{
    const MapAssumeutxo& valid_assumeutxos_map = chainparams.Assumeutxo();
    const auto assumeutxo_found = valid_assumeutxos_map.find(height);

    if (assumeutxo_found != valid_assumeutxos_map.end()) {
        return &assumeutxo_found->second;
    }
    return nullptr;
}

bool ChainstateManager::ActivateSnapshot(
        AutoFile& coins_file,
        const SnapshotMetadata& metadata,
        bool in_memory)
{
    uint256 base_blockhash = metadata.m_base_blockhash;

    if (this->SnapshotBlockhash()) {
        LogPrintf("[snapshot] can't activate a snapshot-based chainstate more than once\n");
        return false;
    }

    int64_t current_coinsdb_cache_size{0};
    int64_t current_coinstip_cache_size{0};

    // Cache percentages to allocate to each chainstate.
    //
    // These particular percentages don't matter so much since they will only be
    // relevant during snapshot activation; caches are rebalanced at the conclusion of
    // this function. We want to give (essentially) all available cache capacity to the
    // snapshot to aid the bulk load later in this function.
    static constexpr double IBD_CACHE_PERC = 0.01;
    static constexpr double SNAPSHOT_CACHE_PERC = 0.99;

    {
        LOCK(::cs_main);
        // Resize the coins caches to ensure we're not exceeding memory limits.
        //
        // Allocate the majority of the cache to the incoming snapshot chainstate, since
        // (optimistically) getting to its tip will be the top priority. We'll need to call
        // `MaybeRebalanceCaches()` once we're done with this function to ensure
        // the right allocation (including the possibility that no snapshot was activated
        // and that we should restore the active chainstate caches to their original size).
        //
        current_coinsdb_cache_size = this->ActiveChainstate().m_coinsdb_cache_size_bytes;
        current_coinstip_cache_size = this->ActiveChainstate().m_coinstip_cache_size_bytes;

        // Temporarily resize the active coins cache to make room for the newly-created
        // snapshot chain.
        this->ActiveChainstate().ResizeCoinsCaches(
            static_cast<size_t>(current_coinstip_cache_size * IBD_CACHE_PERC),
            static_cast<size_t>(current_coinsdb_cache_size * IBD_CACHE_PERC));
    }

    auto snapshot_chainstate = WITH_LOCK(::cs_main,
        return std::make_unique<Chainstate>(
            /*mempool=*/nullptr, m_blockman, *this, base_blockhash));

    {
        LOCK(::cs_main);
        snapshot_chainstate->InitCoinsDB(
            static_cast<size_t>(current_coinsdb_cache_size * SNAPSHOT_CACHE_PERC),
            in_memory, false, "chainstate");
        snapshot_chainstate->InitCoinsCache(
            static_cast<size_t>(current_coinstip_cache_size * SNAPSHOT_CACHE_PERC));
    }

    const bool snapshot_ok = this->PopulateAndValidateSnapshot(
        *snapshot_chainstate, coins_file, metadata);

    if (!snapshot_ok) {
        WITH_LOCK(::cs_main, this->MaybeRebalanceCaches());
        return false;
    }

    {
        LOCK(::cs_main);
        assert(!m_snapshot_chainstate);
        m_snapshot_chainstate.swap(snapshot_chainstate);
        const bool chaintip_loaded = m_snapshot_chainstate->LoadChainTip();
        assert(chaintip_loaded);

        m_active_chainstate = m_snapshot_chainstate.get();

        LogPrintf("[snapshot] successfully activated snapshot %s\n", base_blockhash.ToString());
        LogPrintf("[snapshot] (%.2f MB)\n",
            m_snapshot_chainstate->CoinsTip().DynamicMemoryUsage() / (1000 * 1000));

        this->MaybeRebalanceCaches();
    }
    return true;
}

static void FlushSnapshotToDisk(CCoinsViewCache& coins_cache, bool snapshot_loaded)
{
    LOG_TIME_MILLIS_WITH_CATEGORY_MSG_ONCE(
        strprintf("%s (%.2f MB)",
                  snapshot_loaded ? "saving snapshot chainstate" : "flushing coins cache",
                  coins_cache.DynamicMemoryUsage() / (1000 * 1000)),
        BCLog::LogFlags::ALL);

    coins_cache.Flush();
}

bool ChainstateManager::PopulateAndValidateSnapshot(
    Chainstate& snapshot_chainstate,
    AutoFile& coins_file,
    const SnapshotMetadata& metadata)
{
    // It's okay to release cs_main before we're done using `coins_cache` because we know
    // that nothing else will be referencing the newly created snapshot_chainstate yet.
    CCoinsViewCache& coins_cache = *WITH_LOCK(::cs_main, return &snapshot_chainstate.CoinsTip());

    uint256 base_blockhash = metadata.m_base_blockhash;

    CBlockIndex* snapshot_start_block = WITH_LOCK(::cs_main, return m_blockman.LookupBlockIndex(base_blockhash));

    if (!snapshot_start_block) {
        // Needed for ComputeUTXOStats and ExpectedAssumeutxo to determine the
        // height and to avoid a crash when base_blockhash.IsNull()
        LogPrintf("[snapshot] Did not find snapshot start blockheader %s\n",
                  base_blockhash.ToString());
        return false;
    }

    int base_height = snapshot_start_block->nHeight;
    auto maybe_au_data = ExpectedAssumeutxo(base_height, GetParams());

    if (!maybe_au_data) {
        LogPrintf("[snapshot] assumeutxo height in snapshot metadata not recognized " /* Continued */
                  "(%d) - refusing to load snapshot\n", base_height);
        return false;
    }

    const AssumeutxoData& au_data = *maybe_au_data;

    COutPoint outpoint;
    Coin coin;
    const uint64_t coins_count = metadata.m_coins_count;
    uint64_t coins_left = metadata.m_coins_count;

    LogPrintf("[snapshot] loading coins from snapshot %s\n", base_blockhash.ToString());
    int64_t coins_processed{0};

    while (coins_left > 0) {
        try {
            coins_file >> outpoint;
            coins_file >> coin;
        } catch (const std::ios_base::failure&) {
            LogPrintf("[snapshot] bad snapshot format or truncated snapshot after deserializing %d coins\n",
                      coins_count - coins_left);
            return false;
        }
        if (coin.nHeight > base_height ||
            outpoint.n >= std::numeric_limits<decltype(outpoint.n)>::max() // Avoid integer wrap-around in coinstats.cpp:ApplyHash
        ) {
            LogPrintf("[snapshot] bad snapshot data after deserializing %d coins\n",
                      coins_count - coins_left);
            return false;
        }

        coins_cache.EmplaceCoinInternalDANGER(std::move(outpoint), std::move(coin));

        --coins_left;
        ++coins_processed;

        if (coins_processed % 1000000 == 0) {
            LogPrintf("[snapshot] %d coins loaded (%.2f%%, %.2f MB)\n",
                coins_processed,
                static_cast<float>(coins_processed) * 100 / static_cast<float>(coins_count),
                coins_cache.DynamicMemoryUsage() / (1000 * 1000));
        }

        // Batch write and flush (if we need to) every so often.
        //
        // If our average Coin size is roughly 41 bytes, checking every 120,000 coins
        // means <5MB of memory imprecision.
        if (coins_processed % 120000 == 0) {
            if (ShutdownRequested()) {
                return false;
            }

            const auto snapshot_cache_state = WITH_LOCK(::cs_main,
                return snapshot_chainstate.GetCoinsCacheSizeState());

            if (snapshot_cache_state >= CoinsCacheSizeState::CRITICAL) {
                // This is a hack - we don't know what the actual best block is, but that
                // doesn't matter for the purposes of flushing the cache here. We'll set this
                // to its correct value (`base_blockhash`) below after the coins are loaded.
                coins_cache.SetBestBlock(GetRandHash());

                // No need to acquire cs_main since this chainstate isn't being used yet.
                FlushSnapshotToDisk(coins_cache, /*snapshot_loaded=*/false);
            }
        }
    }

    // Important that we set this. This and the coins_cache accesses above are
    // sort of a layer violation, but either we reach into the innards of
    // CCoinsViewCache here or we have to invert some of the Chainstate to
    // embed them in a snapshot-activation-specific CCoinsViewCache bulk load
    // method.
    coins_cache.SetBestBlock(base_blockhash);

    bool out_of_coins{false};
    try {
        coins_file >> outpoint;
    } catch (const std::ios_base::failure&) {
        // We expect an exception since we should be out of coins.
        out_of_coins = true;
    }
    if (!out_of_coins) {
        LogPrintf("[snapshot] bad snapshot - coins left over after deserializing %d coins\n",
            coins_count);
        return false;
    }

    LogPrintf("[snapshot] loaded %d (%.2f MB) coins from snapshot %s\n",
        coins_count,
        coins_cache.DynamicMemoryUsage() / (1000 * 1000),
        base_blockhash.ToString());

    // No need to acquire cs_main since this chainstate isn't being used yet.
    FlushSnapshotToDisk(coins_cache, /*snapshot_loaded=*/true);

    assert(coins_cache.GetBestBlock() == base_blockhash);

    auto breakpoint_fnc = [] { /* TODO insert breakpoint here? */ };

    // As above, okay to immediately release cs_main here since no other context knows
    // about the snapshot_chainstate.
    CCoinsViewDB* snapshot_coinsdb = WITH_LOCK(::cs_main, return &snapshot_chainstate.CoinsDB());

    const std::optional<CCoinsStats> maybe_stats = ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, snapshot_coinsdb, m_blockman, breakpoint_fnc);
    if (!maybe_stats.has_value()) {
        LogPrintf("[snapshot] failed to generate coins stats\n");
        return false;
    }

    // Assert that the deserialized chainstate contents match the expected assumeutxo value.
    if (AssumeutxoHash{maybe_stats->hashSerialized} != au_data.hash_serialized) {
        LogPrintf("[snapshot] bad snapshot content hash: expected %s, got %s\n",
            au_data.hash_serialized.ToString(), maybe_stats->hashSerialized.ToString());
        return false;
    }

    snapshot_chainstate.m_chain.SetTip(*snapshot_start_block);

    // The remainder of this function requires modifying data protected by cs_main.
    LOCK(::cs_main);

    // Fake various pieces of CBlockIndex state:
    CBlockIndex* index = nullptr;

    // Don't make any modifications to the genesis block.
    // This is especially important because we don't want to erroneously
    // apply BLOCK_ASSUMED_VALID to genesis, which would happen if we didn't skip
    // it here (since it apparently isn't BLOCK_VALID_SCRIPTS).
    constexpr int AFTER_GENESIS_START{1};

    for (int i = AFTER_GENESIS_START; i <= snapshot_chainstate.m_chain.Height(); ++i) {
        index = snapshot_chainstate.m_chain[i];

        // Fake nTx so that LoadBlockIndex() loads assumed-valid CBlockIndex
        // entries (among other things)
        if (!index->nTx) {
            index->nTx = 1;
        }
        // Fake nChainTx so that GuessVerificationProgress reports accurately
        index->nChainTx = index->pprev->nChainTx + index->nTx;

        // Mark unvalidated block index entries beneath the snapshot base block as assumed-valid.
        if (!index->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This flag will be removed once the block is fully validated by a
            // background chainstate.
            index->nStatus |= BLOCK_ASSUMED_VALID;
        }

        // Fake BLOCK_OPT_WITNESS so that Chainstate::NeedsRedownload()
        // won't ask to rewind the entire assumed-valid chain on startup.
        if (DeploymentActiveAt(*index, *this, Consensus::DEPLOYMENT_SEGWIT)) {
            index->nStatus |= BLOCK_OPT_WITNESS;
        }

        m_blockman.m_dirty_blockindex.insert(index);
        // Changes to the block index will be flushed to disk after this call
        // returns in `ActivateSnapshot()`, when `MaybeRebalanceCaches()` is
        // called, since we've added a snapshot chainstate and therefore will
        // have to downsize the IBD chainstate, which will result in a call to
        // `FlushStateToDisk(ALWAYS)`.
    }

    assert(index);
    index->nChainTx = au_data.nChainTx;
    snapshot_chainstate.setBlockIndexCandidates.insert(snapshot_start_block);

    LogPrintf("[snapshot] validated snapshot (%.2f MB)\n",
        coins_cache.DynamicMemoryUsage() / (1000 * 1000));
    return true;
}

Chainstate& ChainstateManager::ActiveChainstate() const
{
    LOCK(::cs_main);
    assert(m_active_chainstate);
    return *m_active_chainstate;
}

bool ChainstateManager::IsSnapshotActive() const
{
    LOCK(::cs_main);
    return m_snapshot_chainstate && m_active_chainstate == m_snapshot_chainstate.get();
}

void ChainstateManager::MaybeRebalanceCaches()
{
    AssertLockHeld(::cs_main);
    if (m_ibd_chainstate && !m_snapshot_chainstate) {
        LogPrintf("[snapshot] allocating all cache to the IBD chainstate\n");
        // Allocate everything to the IBD chainstate.
        m_ibd_chainstate->ResizeCoinsCaches(m_total_coinstip_cache, m_total_coinsdb_cache);
    }
    else if (m_snapshot_chainstate && !m_ibd_chainstate) {
        LogPrintf("[snapshot] allocating all cache to the snapshot chainstate\n");
        // Allocate everything to the snapshot chainstate.
        m_snapshot_chainstate->ResizeCoinsCaches(m_total_coinstip_cache, m_total_coinsdb_cache);
    }
    else if (m_ibd_chainstate && m_snapshot_chainstate) {
        // If both chainstates exist, determine who needs more cache based on IBD status.
        //
        // Note: shrink caches first so that we don't inadvertently overwhelm available memory.
        if (m_snapshot_chainstate->IsInitialBlockDownload()) {
            m_ibd_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.05, m_total_coinsdb_cache * 0.05);
            m_snapshot_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.95, m_total_coinsdb_cache * 0.95);
        } else {
            m_snapshot_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.05, m_total_coinsdb_cache * 0.05);
            m_ibd_chainstate->ResizeCoinsCaches(
                m_total_coinstip_cache * 0.95, m_total_coinsdb_cache * 0.95);
        }
    }
}

ChainstateManager::~ChainstateManager()
{
    LOCK(::cs_main);

    m_versionbitscache.Clear();

    // TODO: The warning cache should probably become non-global
    for (auto& i : warningcache) {
        i.clear();
    }
}

////////////////////////////////////////////////////////////////////////////////// // runebase
bool GetAddressIndex(uint256 addressHash, int type, std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex, node::BlockManager& blockman, int start, int end)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    if (!blockman.m_block_tree_db->ReadAddressIndex(addressHash, type, addressIndex, start, end))
        return error("unable to get txids for address");

    return true;
}

bool GetSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value, const CTxMemPool& mempool, node::BlockManager& blockman)
{
    if (!fAddressIndex)
        return false;

    if (mempool.getSpentIndex(key, value))
        return true;

    if (!blockman.m_block_tree_db->ReadSpentIndex(key, value))
        return false;

    return true;
}

bool GetAddressUnspent(uint256 addressHash, int type, std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs, node::BlockManager& blockman)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    if (!blockman.m_block_tree_db->ReadAddressUnspentIndex(addressHash, type, unspentOutputs))
        return error("unable to get txids for address");

    return true;
}

bool GetTimestampIndex(const unsigned int &high, const unsigned int &low, const bool fActiveOnly, std::vector<std::pair<uint256, unsigned int> > &hashes, ChainstateManager& chainman)
{
    if (!fAddressIndex)
        return error("Timestamp index not enabled");

    if (!chainman.m_blockman.m_block_tree_db->ReadTimestampIndex(high, low, fActiveOnly, hashes, chainman))
        return error("Unable to get hashes for timestamps");

    return true;
}

CAmount GetTxGasFee(const CMutableTransaction& _tx, const CTxMemPool& mempool, Chainstate& active_chainstate)
{
    CTransaction tx(_tx);
    CAmount nGasFee = 0;
    if(tx.HasCreateOrCall())
    {
        LOCK(cs_main);
        const CChainParams& chainparams = Params();
        unsigned int contractflags = GetContractScriptFlags(active_chainstate.m_chain.Height() + 1, chainparams.GetConsensus());
        RunebaseTxConverter convert(tx, active_chainstate, &mempool, NULL, NULL, contractflags);

        ExtractRunebaseTX resultConvertRunebaseTX;
        if(!convert.extractionRunebaseTransactions(resultConvertRunebaseTX)){
            return nGasFee;
        }

        dev::u256 sumGas = dev::u256(0);
        for(RunebaseTransaction& qtx : resultConvertRunebaseTX.first){
            sumGas += qtx.gas() * qtx.gasPrice();
        }

        nGasFee = (CAmount) sumGas;
    }
    return nGasFee;
}

bool GetAddressWeight(uint256 addressHash, int type, const std::map<COutPoint, uint32_t>& immatureStakes, int32_t nHeight, uint64_t& nWeight, node::BlockManager& blockman)
{
    nWeight = 0;

    if (!fAddressIndex)
        return error("address index not enabled");

    // Get address utxos
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    if (!GetAddressUnspent(addressHash, type, unspentOutputs, blockman)) {
        throw error("No information available for address");
    }

    // Add the utxos to the list if they are mature
	const Consensus::Params& consensusParams = Params().GetConsensus();
    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator i=unspentOutputs.begin(); i!=unspentOutputs.end(); i++) {

        int nDepth = nHeight - i->second.blockHeight + 1;
        if (nDepth < consensusParams.CoinbaseMaturity(nHeight + 1))
            continue;

        if(i->second.satoshis < 0)
            continue;

        COutPoint prevout = COutPoint(i->first.txhash, i->first.index);
        if(immatureStakes.find(prevout) == immatureStakes.end())
        {
            nWeight+= i->second.satoshis;
        }
    }

    return true;
}

std::map<COutPoint, uint32_t> GetImmatureStakes(ChainstateManager& chainman)
{
    std::map<COutPoint, uint32_t> immatureStakes;
    int height = chainman.ActiveChain().Height();
    int coinbaseMaturity = Params().GetConsensus().CoinbaseMaturity(height + 1);
    for(int i = 0; i < coinbaseMaturity -1; i++) {
        CBlockIndex* block = chainman.ActiveChain()[height - i];
        if(block)
        {
            immatureStakes[block->prevoutStake] = block->nTime;
        }
        else
        {
            break;
        }
    }
    return immatureStakes;
}
//////////////////////////////////////////////////////////////////////////////////

