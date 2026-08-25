# Option 4 — optimistic (fraud-proof) bridge

The fallback pattern when full verification of the counterparty is too
heavy: accept claims after a challenge window, let **anyone** disprove a
false claim with a fraud proof. Trust model: **1-of-N honest watcher** — not
"trust the relayer", but "at least one honest party exists and is awake."
This satisfies the project constraint (no trusted relayer set: any single
honest actor defeats all dishonest ones), but it is strictly weaker than
options 2/3, and is documented here mainly to mark the boundary of what we
consider acceptable.

## How it works

1. A relayer (anyone) posts "chain A finalized root R at height H" on
   chain B, bonded with a stake.
2. A challenge window opens (hours-days).
3. Any watcher can submit a fraud proof — for Runebase-origin claims, a
   header chain showing the claimed root is not in the canonical chain;
   the poster's bond is slashed and paid to the challenger.
4. Unchallenged claims finalize; state proofs against R then release
   funds.

Because Runebase headers commit to the EVM state root, fraud proofs about
Runebase state are compact: header chain + MPT proof. For disputes *hosted
on* Runebase, contracts can check re-orgs against the last **8191 block
hashes (~3 days at 32s)** via the EIP-2935 history precompile (verified
live during the v29.1 work) — an in-EVM upper bound on challenge windows
that reference Runebase block identity. The economically
rational-relayer assumption does the day-to-day work; the watcher ecosystem
is the safety net.

## Honest assessment

- **Latency is the price:** withdrawals wait out the challenge window.
- **Implementation risk is the killer:** Nomad (2022, ~$190M) fell to a
  fraud-proof implementation bug, not to its trust model. An optimistic
  bridge is only as good as the audit of its proof-verification path.
- **Liveness assumption:** censoring all challengers for the whole window
  (e.g. sustained spam on the destination chain) is the theoretical
  attack; long windows and challenger diversity are the mitigations.
- It shares the outbound reality of options 2/3: a fraud proof about
  Runebase's canonical chain is only as strong as what a remote verifier
  can check about PoSv3 headers — the same weak-subjectivity checkpoint
  logic applies to the fraud-proof verifier.

## When it would make sense

- As a **fast-path overlay** on option 2/3 rails (optimistic acceptance
  with zk/light-client fallback as the dispute arbiter) — several
  production systems converge on this hybrid.
- As a stopgap to a chain we cannot yet verify cryptographically.

**Recommendation:** do not build standalone. Revisit as an optimization
layer once option 2 or 3 rails exist, reusing their verifiers as the
dispute backstop.
