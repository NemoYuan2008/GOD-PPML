# AGENTS.md

## Project context

This repository is an MP-SPDZ fork used to implement an honest-majority,
\(n\)-party PPML protocol with guaranteed output delivery (GOD), by adapting
the existing GS20/Atlas-based malicious-with-abort implementation toward
GSZ20.

The main implementation files are usually:

- `Protocols/AtlasGsz.h`
- `Protocols/AtlasGsz.hpp`

Related files may include:

- `Protocols/AtlasGszShare.h`
- `Protocols/Atlas.h`
- `Protocols/Atlas.hpp`
- `Protocols/Shamir.h`
- `Protocols/Shamir.hpp`
- `Protocols/ShamirInput.h`
- `Protocols/ShamirInput.hpp`
- `Programs/Source/0-mul-input.py`
- `Programs/Source/0-dot.py`
- `Programs/Source/0-dot-input.py`

Do not add a separate protocol implementation or broadly refactor unrelated
MP-SPDZ code unless the milestone explicitly requests it.

The GSZ20 paper is located at ~/papers/GSZ20.pdf

The LaTeX project (contains the technical core) of my GOD PPML paper is located at ~/papers/GOD-PPML-paper

The implementation of original GS20 (security with abort) is at ~/papers/Malicious-Scalable-PPML

## Source-of-truth hierarchy

When implementation choices affect terminology, protocol structure, ownership,
batching, state transitions, or security claims, use the following hierarchy:

1. the current GOD-PPML LaTeX technical core;
2. `GOD_CONTROL_PLANE_MAP.md`, the paper-to-code architecture contract;
3. GSZ20 for the concrete GOD/FTag realization where the technical core is
   abstract;
4. GS20 and the existing TDSC implementation for the underlying
   malicious-with-abort PPML machinery;
5. existing C++ metadata, which is an implementation inventory rather than an
   independent semantic specification.

Do not silently choose an answer for an issue marked unresolved in the
technical core or control-plane contract. Report the ambiguity instead.

## Protocol strategy

Implementation is divided into two stages.

### Stage 1: optimistic honest execution

The current priority is the complete path executed when all parties behave
honestly, including real computation and communication for:

- segment evaluation;
- multiplication and dot-product transcript collection;
- virtual-transcript construction and segment verification;
- dealer-source authentication;
- checkpoint-tag generation and checking;
- authenticated source handles;
- checkpoint derivations, sealing, and promotion;
- continuation to later segments;
- final output gating.

Operations that always execute in an honest run must not be represented only
by metadata, because their communication and running time are part of the
experiments.

### Stage 2: adversarial recovery

Unless a milestone explicitly requests them, do not implement:

- real `Analyze-Sharing`;
- localization of inconsistent dealer sharings;
- corrupted-party or disputed-pair identification;
- mutation of `Corr` or `Disp`;
- rollback, retry, or segment re-evaluation;
- relay communication;
- execution after `Corr` becomes nonempty;
- complete `Refresh`/surgery recovery;
- repeated adversarial failures and exclusion.

Until Stage 2 exists, failures in the Stage-1 path must be fail-stop:

1. retain a clear failure class and relevant diagnostics;
2. create no authenticated handles for a failed batch;
3. do not seal or promote the affected checkpoint;
4. do not clear the failure state;
5. terminate with `RecoveryNotImplemented` or the repository’s equivalent;
6. do not claim that recovery, rollback, or `Analyze-Sharing` succeeded.

The implementation must not be described as a complete GOD implementation.
Use terminology such as:

> implementation of the optimistic execution path of the GOD protocol,
> including segment verification and authenticated checkpoints.

## Mandatory provenance invariant

The authoritative provenance direction is:

```text
dealer-generated source batch
    -> VShare.Authenticate / real FTag execution
    -> stable authenticated source handles
    -> public linear derivations
    -> checkpoint outputs
```

Never reverse this direction.

In particular:

- do not authenticate a derived checkpoint output as a newly dealt source;
- do not authenticate a published failure snapshot after the failure;
- do not create handles from rejected or merely planned authentication;
- `VShare.Analyze` must eventually consume existing handles plus a derivation
  and claims; it must not manufacture new authenticated sources.

A stable source handle is semantically:

```text
(batch_id, dealer_id, source_ordinal)
```

## Current implementation boundary

The repository contains working GS20/Atlas verification machinery, including
multiplication and dot-product transcript collection, virtual-transcript
construction, and the optimized ultimate-tuple success path.

It also contains an opt-in, real, **global optimistic FTag vertical slice**,
exercised through focused runtime hooks. The same authentication algorithm now
has two component paths: a source-only path that atomically commits
authenticated source handles without creating a checkpoint, and the existing
checkpoint-coupled path that additionally validates derivations and promotes a
checkpoint. The slice includes:

- authoritative ordered dealer-source batches;
- restricted `e = 1` dealer Verify-Sharing over each exact unpadded source
  batch, executed before key and tag work;
- restricted `e = 1` consistency checking for each transient `B`-component
  BaseSharing before any `check_mask=true` tag material is generated;
- a configurable, session-immutable base-field FTag chunk width `B`, defaulting
  to `4` and focused-overridable with `ATLAS_GSZ_FTAG_CHUNK_WIDTH`; this is not
  extension-field packing. The default value `4` is retained by the current
  code but is not an acceptable production or experimental parameter for large
  workloads. Any reported communication experiment must state the explicit
  value of `ATLAS_GSZ_FTAG_CHUNK_WIDTH`;
- one reusable verifier-holder `mu` key epoch;
- restricted `e = 1` Check-Key with a fresh uniform twisted mask `rho`;
- a newly and independently uniformly sampled `nu` for each
  batch/chunk/verifier/holder relation; accidental equality between
  independently sampled field elements is allowed and is not reuse;
- real twisted-sharing MPC tag computation;
- holder-only tag reconstruction;
- one global all-dealer/all-batch Check-Tag challenge and aggregate check for
  the exact pending dealer-source batches required by one checkpoint;
- canonical ascending dealer order and the uniform exponent layout
  `position(r,k) = r * (W + 1) + k`, with one checked BaseSharing at `k=0`
  and only real source chunks at `k=1,...,w_r`;
- one aggregate `B`-vector and one aggregate tag scalar per holder-to-verifier
  relation, with zero permitted for the shared Protocol-27 challenge;
- one compact Protocol-27 decision per verifier (`ok` or that verifier's
  smallest rejected holder), broadcast in one decision round; the public
  payload is not a vector of verifier-holder Boolean results;
- authenticated source handles assigned only after success;
- an independently invocable source-only handle-commit path using
  `checkpoint_id == 0` as the explicit no-checkpoint sentinel;
- public linear checkpoint derivations over those handles;
- unsealed checkpoint candidates that seal and promote only after validation;
- fail-stop `RecoveryNotImplemented` behavior on authentication failure.

The producer side also exposes neutral, atomic provenance for each completed
`Shamir::get_randoms()` call and pairs the degree-`t`/degree-`2t` records for
buffered Atlas DoubleRand materials. This records original unscaled dealer
sources and exact public hyper-matrix derivations. Each completed concrete
Atlas multiplication or dot-product-family operation now exposes the exact
consumed material's shared producer record and producer output ordinal to
AtlasGsz, which retains that private-process reference in its real wrapper
record. This transfer does not create tentative capture state, dealer batches,
authentication, handles, derivations over handles, FTag chunks, checkpoints,
or scheduler state.

The fixed-king ordinary scalar-multiplication and dot-product path now
constructs the exact special sharing `[e]^T_t`: for the current optimistic
no-dispute king 0, `T={0,...,t}` in canonical numeric order, every share
outside `T` is zero, and the construction consumes no randomness. The
concrete transcript retains this public support and the king retains the exact
full distributed vector as private evidence. The opt-in tentative adapter now
captures and authenticates this concrete `e_t` source for ordinary scalar and
dot operations. This does not implement `Corr`/`Disp`-aware support selection
or continued execution.

AtlasGsz also contains an opt-in tentative DoubleRand source-capture vertical
slice for completed ordinary scalar multiplication and ordinary dot-product
wrapper records. One focused round assigns producer-record ordinals by
completed-operation encounter order, rejects duplicate exact consumed outputs,
deduplicates whole degree-`t` dealer source groups, aggregates one original
local source share per real dealer in deterministic producer/group order, and
forms temporary derivations over candidate-local source references for each
consumed `r_t`. Each consumed output also retains one narrow concrete `e_t`
source record containing the real king, public support, and local source share,
cross-checked against the exact retained real wrapper record and king-only
evidence. Paired degree-`2t` provenance remains validation/evidence only. The
tentative candidate can be finalized atomically, inspected, and discarded.

The repository now also contains one opt-in, consuming adapter from that exact
finalized candidate to the existing source-only authentication path. After a
complete local preflight, it copies one ordered source sequence into one
`DealerSourceBatchRecord` per real dealer, claims the candidate, atomically
appends the complete ascending-dealer batch set, advances `next_batch_id` once,
and invokes `authenticate_source_batches()` exactly once. On success it returns
a value receipt mapping
`(producer_record_ordinal, input_generation_group_ordinal, dealer)` to the exact
authenticated handle, in producer/group/dealer order, plus an ascending-dealer
`(dealer, batch_id, source_count)` summary. The receipt contains public numeric
identities only and is not a persistent mapping registry.

The DoubleRand candidate table remains equal-width with `q` sources per real
dealer. During adapter preflight only, the real king's one prospective batch is
extended by the captured `e_t` sources in capture order, at ordinals
`q,...,q+m-1`; other real dealers retain exactly `q` sources. There is no
second king batch, synthetic dealer, padding source, or second authentication
invocation.

While the adapter's stack-local claimed candidate is still alive, it also
converts every captured degree-`t` `r_t` derivation into an ordered
`LinearDerivation` over the exact committed handles. The complete result shape,
coefficients, and numeric term-to-receipt indices are allocated and validated
before candidate claim or authentication. Handles are assigned only after the
existing source-only authentication commits, followed by direct authoritative
batch validation and a local equality check against the captured `actual_r_t`.
The converted values are returned by value in the adapter receipt; there is no
persistent derivation or checkpoint registry. The receipt also returns one
direct authenticated king-source handle per captured operation; it does not
wrap `e_t` in a one-term derivation. For each captured ordinary scalar or dot
operation, the receipt additionally returns the exact ordered handle-based
derivation `Delta_z = (1, h_e) - Delta_r`. This is a by-value receipt result:
it creates no new source, handle, checkpoint, or persistent registry.

The capture alone still creates no dealer batch or batch ID, authenticated
source handle, FTag chunk, authentication invocation, checkpoint, or scheduler
state. Only the opt-in adapter consumes the finalized candidate and enters the
source-only authentication path. Malformed preflight discards the candidate
before any authentication mutation or execution. Authentication rejection
retains the registered diagnostic records and fail-stop evidence, creates no
handles, and does not permit reuse or retry.

Eligible ordinary scalar-multiplication and ordinary dot-product operations
are now integrated through one explicit logical online segment. The existing
`AtlasConfig::max_before_check` / `maybe_check()` / `check()` lifecycle remains
an internal GS20 memory/verification boundary only. Each successfully verified
ordinary candidate is transferred into one segment-owned collector without
authentication. At segment close, one communication-free structural preflight
deduplicates exact whole DoubleRand producer groups, reads each producer
group's actual output count, forms one ordered source sequence per real dealer,
and appends every direct concrete `e_t` source to king 0's existing dealer
sequence. The collector then invokes the existing global source-only
authentication exactly once.

After authentication success, the exact `r_t`, direct `e_t`, and `z_t`
bindings are validated against committed handles. The ordered ordinary `z_t`
live-outs form one checkpoint candidate, which seals and promotes only after
all derivations resolve. Successful cleanup retires internal verification
state, tentative producer/candidate state, receipt-local mappings, fresh `nu`,
holder tags, and the successful global-invocation presentation. Authenticated
dealer batches/handles, the promoted checkpoint, reusable checked `mu` keys,
their epoch, agreed FTag width, monotonic IDs, PRNG state, and cumulative public
counters persist.

Unsupported operation families remain GS20-only and force an eligible ordinary
batch boundary before entering. `max_before_check` still counts `x_verify`
coordinates rather than operations, so a single dot product can cross or
overshoot it while producing one captured operation and one concrete king
`e_t` source. Focused integration tests use a test-only effective threshold
and an explicit segment close after the final residual flush. Destructor-time
close remains only a fallback for workloads without a scheduler hook and is
not a production pre-output gate.

This one-worker, one-segment ordinary lifecycle is not a complete
segment/checkpoint scheduler and must not be described as the complete GSZ20
authentication path.

The following honest-path items remain unimplemented:

1. segment-wide source collection and checkpoint live-outs for deferred
   operation families;
2. continuation across more than one logical segment and normal scheduler
   integration;
3. final production output gating through that scheduler.

Truncation, mul-public, virtual-transcript, compression-generated, and
ultimate-tuple provenance remain deferred.

The current ordinary collector merges the king's PartialMult-dealt degree-`t`
`e_t` sources with that same real party's other dealer sources and must remain
free of any second logical dealer for the king.

Legacy authentication, recovery, and Analyze-related metadata skeletons remain
in the code. They are not authoritative production provenance. Do not build
new cryptographic execution on an incorrect legacy abstraction merely to
minimize a diff.


## Current communication-efficiency audit status

The first optimistic ordinary scalar/dot segment path and its runtime
corrections are committed.

The current implementation now has:

- internal GS20 verification batches that do not authenticate themselves;
- one segment-owned ordinary scalar/dot source collector;
- exactly one source-only authentication invocation when the current logical
  segment closes;
- exact producer-group deduplication using the concrete producer output count;
- one real dealer batch per party, with the king's DoubleRand sources and
  direct `e_t` sources concatenated into the king's batch;
- committed authenticated source handles;
- handle-based `r_t`, direct `e_t`, and `z_t=e_t-r_t` derivations;
- one sealed/promoted ordinary checkpoint;
- one reusable `mu` key epoch and fresh per-chunk `nu`;
- communication, runtime, and memory audit modes;
- O(1) authenticated-handle validation by source ordinal;
- one-pass producer-group width calculation;
- memory estimation disabled during normal execution.

The previously introduced runtime regression has been resolved. For
`Programs/Source/1-net-a` with three parties and
`ATLAS_GSZ_FTAG_CHUNK_WIDTH=320`, normal execution is approximately 2.7
seconds, compared with approximately 2.4 seconds before real authentication
was integrated. Authentication communication and protocol behavior were
unchanged by the runtime correction.

### Unresolved communication problem

The remaining primary issue is the communication cost and party-count scaling
of the real authentication/FTag realization.

For the same `1-net-a` workload:

- the original GS20 implementation communicates approximately 12.2587 MB
  globally at 15 parties;
- the GOD implementation immediately before real authentication was wired into
  ordinary execution was nearly identical to GS20;
- the current restricted authentication path, after segment collection and
  width tuning, communicates approximately 55.57 MB at 15 parties, with the
  best measured width near `B=448`;
- the historical/default `B=4` configuration is pathological and produced
  approximately 1,039 MB at 15 parties.

Therefore the GS20 computation, virtual transcripts, and local provenance
bookkeeping are not the source of the large communication gap. The unresolved
cost comes from the current real FTag/source-authentication realization.

Do not claim that the 55.57 MB result is inevitable, paper-faithful, linear in
the number of parties, or representative of GSZ20's `5.5+epsilon` concrete
claim until the protocol-to-code correspondence has been audited.

The current implementation uses the restricted setting:

```text
F = K = F_(2^61-1)
e = 1
```

and an implementation parameter `B` described as a base-field chunk width.
It has not yet been established that `B` corresponds exactly to the paper's
`ell`, to `q=ell/e`, or to the complete batching schedule of GSZ20 `Tag`.

### Current audit milestone

The next milestone is analysis-only. Before modifying code, compare the
current implementation against GSZ20's:

- FTag;
- Verify-Sharing;
- Check-Key;
- BaseSharing;
- Check-Tag;
- complete Tag realization;
- Comp-Seg scheduling.

The audit must determine:

- which implementation messages correspond to each paper protocol;
- which costs are per session, segment, dealer, chunk, verifier, and holder;
- whether the current dealer × chunk × verifier × holder communication is
  exactly required;
- whether the paper amortizes or avoids any current communication;
- whether extension-field packing is required;
- whether the `O(n^2)` segment partition is relevant to honest-path
  communication or primarily to retry bounds;
- the expected cost of a paper-faithful realization for the exact `1-net-a`
  workload.

Do not, before this audit is complete:

- split the current collector into `n^2` segments;
- redesign FTag;
- remove protocol messages merely to reduce measurements;
- hard-code another width as proof of paper fidelity;
- describe the restricted `e=1` path as the complete GSZ20 Tag protocol;
- revisit the resolved quadratic runtime issue.

### Build configuration

Use the normal working build for all communication audits:

- keep `NDEBUG` undefined;
- retain `-Werror`;
- perform a clean rebuild when changing compiler flags.

The current repository is not `NDEBUG`-clean. Defining `NDEBUG` produces
unused-variable errors under `-Werror`, and after suppressing those errors the
compiled `1-net-a` execution fails while reading
`Player-Data/Input-Binary-P0-1`. Restoring the normal build makes the workload
succeed.

Treat `NDEBUG` compatibility as a separate deferred release-engineering
milestone. Assertions and debug-only checks are local computation and must not
be used to explain network communication.

## Critical implementation constraints

### Preserve the optimized ultimate-tuple opening

Do not undo the optimized ultimate-tuple success path.

It must:

1. use `malicious_mc.POpen()` to open only `(alpha, beta, gamma)`;
2. return immediately when `alpha * beta == gamma`;
3. call `broadcast_local_shares(ultimate_tuple)` only after that optimized
   check fails.

Do not restore unconditional publication of the complete virtual transcript.

### Preserve role ownership

Production state must respect protocol ownership:

- verifier \(P_v\) owns clear long-term `mu_(v->i)`;
- verifier \(P_v\) owns freshly sampled per-batch/chunk `nu`;
- holder \(P_i\) owns the reconstructed tag;
- non-holder parties retain only the local twisted shares needed for MPC;
- ordinary production records must not co-locate clear `mu`, clear `nu`,
  holder tag, and holder source-share vectors.

Test-only diagnostics must be narrowly scoped and must not print or retain
private authentication material.

### Preserve key reuse and batching

- Reuse one `mu_(v->i)` vector across batches and successful segments in the
  same key epoch.
- Never regenerate `mu` per wire, dealer batch, checkpoint, or segment unless
  a later, explicitly specified key-rotation rule requires it.
- Independently sample fresh `nu` for every authenticated dealer-batch chunk
  and applicable verifier-holder relation.
- Accidental equality between independent `nu` samples is allowed. Reuse means
  reusing the same randomness instance or material record for another batch or
  chunk.
- Authentication instances must scale with batch chunks, not with
  `wire × verifier × holder`.
- The current global checker covers one source-batch authentication invocation,
  either source-only or checkpoint-coupled, while `Corr` and `Disp` remain
  empty. Do not call this focused optimistic vertical slice the complete GSZ20
  `TAG` protocol.
- For `m` dealers and `W=max_r w_r`, the global polynomial identity has
  maximum degree at most `m * (W + 1) - 1`. Concrete soundness depends on
  `p=2^61-1` and union bounds over all verifier-holder relations and
  invocations; do not claim arbitrary kappa-bit soundness.

### Communication and randomness discipline

Do not add new production communication, opening, broadcast, exchange,
send/receive, or randomness calls unless the milestone explicitly requires
real protocol execution that needs them.

When a milestone authorizes new communication:

- use normal MP-SPDZ networking/accounting paths;
- preserve protocol message ordering;
- explain the ownership and destination of each message class;
- ensure the cost appears in communication measurements;
- avoid debug broadcasts that leak private values;
- keep failure-only diagnostic publication off the honest path.

Avoid new uses of the following unless justified by the milestone:

- `POpen`
- `Broadcast_Receive`
- `Check_Broadcast`
- `exchange`
- direct `send` / `receive`
- `get_random` or new PRNG streams

### State and architecture discipline

- Prefer one authoritative record plus small transient results.
- Do not add another chain of plan/readiness/attempt/receipt metadata unless it
  is genuinely required for real execution.
- Use IDs and references rather than copying the same identity graph into many
  records.
- A checkpoint ID alone does not make a checkpoint sealed.
- A checkpoint becomes sealed only after all referenced derivations resolve to
  authenticated source handles and all required checks succeed.
- Failed, pending, or incomplete checkpoints remain unsealed and unpromoted.
- Do not silently mix logical segment identity with retry-attempt identity in
  new code.
- Do not clear retained failure evidence merely to make a later check pass.

## Workflow rules

Before editing, run:

```sh
git status --short
git rev-parse HEAD
```

If the working tree is not clean, stop and report unless the milestone
explicitly says to continue from the current staged or unstaged patch.

Never reset, stash, discard, stage, unstage, commit, amend, or rewrite history
unless explicitly instructed.

Before changing code:

1. inspect the relevant current implementation;
2. identify the exact paper protocol being realized;
3. state which existing helpers will be reused;
4. state what real communication/randomness will be introduced;
5. state the expected failure semantics;
6. give a concise implementation plan.

Prefer small, reviewable, milestone-sized diffs. Modify only files permitted by
the milestone. Explain before touching any additional file.

Do not commit changes unless explicitly asked.

## Build and test rules

After editing, run at least:

```sh
git diff --check
make -j6 atlas-gsz-party.x
```

If there are staged changes, also run:

```sh
git diff --cached --check
```

Compile a program again when switching test programs because `compile.py`
overwrites the previous program input.

Typical smoke-test workflow:

```sh
conda run -n pytorch ./compile.py 0-mul-input
./Scripts/atlas-gsz.sh 0-mul-input

conda run -n pytorch ./compile.py 0-dot
./Scripts/atlas-gsz.sh 0-dot

conda run -n pytorch ./compile.py 0-dot-input
./Scripts/atlas-gsz.sh 0-dot-input
```

Use the repository’s supported party-count convention, for example:

```sh
./Scripts/atlas-gsz.sh -N 5 0-dot
```

or, where the current script/test setup uses it:

```sh
PLAYERS=5 ./Scripts/atlas-gsz.sh 0-dot
```

Expected ordinary output for `0-mul-input`:

```text
63
143
396
```

Expected output for `0-dot` and `0-dot-input`, allowing tiny fixed-point drift:

```text
30
30
30
30
[70, 80, 90]
[30, 36, 42]
[1, 4, 9, 16]
[1, 4, 9]
```

Focused producer-provenance and optimistic-authentication hooks:

```sh
ATLAS_GSZ_AUTH_TEST=producer-provenance PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=producer-provenance PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-dot

ATLAS_GSZ_AUTH_TEST=consumed-provenance-transfer PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-mul-input
ATLAS_GSZ_AUTH_TEST=consumed-provenance-transfer PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-dot

conda run -n pytorch ./compile.py 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-preflight-rejections PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-preflight-rejections PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-auth-rejection PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-auth-rejection PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-gs20-failure PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-gs20-failure PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-unsupported-gs20-failure PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-unsupported-gs20-failure PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-nested-preprocessing PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-nested-preprocessing PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-fixed-king PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-fixed-king PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration

conda run -n pytorch ./compile.py 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-capture PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-capture PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture

ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-honest PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-honest PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-malformed PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-malformed PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-e-t-malformed PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-e-t-malformed PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-verify-failure PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-verify-failure PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-tag-failure PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-tag-failure PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture

ATLAS_GSZ_AUTH_TEST=honest PLAYERS=3 ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=honest PLAYERS=5 ./Scripts/atlas-gsz.sh 0-dot

ATLAS_GSZ_AUTH_TEST=source-only-honest PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=source-only-honest PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=source-only-verify-failure PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=source-only-verify-failure PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=source-only-failure PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=source-only-failure PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-dot

ATLAS_GSZ_FTAG_CHUNK_WIDTH=5 ATLAS_GSZ_AUTH_TEST=honest PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot

ATLAS_GSZ_AUTH_TEST=verify-failure PLAYERS=3 ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=verify-failure PLAYERS=5 ./Scripts/atlas-gsz.sh 0-dot

ATLAS_GSZ_AUTH_TEST=base-failure PLAYERS=3 ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=base-failure PLAYERS=5 ./Scripts/atlas-gsz.sh 0-dot

ATLAS_GSZ_AUTH_TEST=failure PLAYERS=3 ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=failure PLAYERS=5 ./Scripts/atlas-gsz.sh 0-dot

ATLAS_GSZ_AUTH_TEST=singleton-honest PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=ordinary-failure PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=base-contribution-failure PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=duplicate-batch PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=duplicate-dealer PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=omission PLAYERS=3 ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=missing-chunk PLAYERS=3 ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=duplicate-chunk PLAYERS=3 ./Scripts/atlas-gsz.sh 0-dot
ATLAS_GSZ_AUTH_TEST=epoch-mismatch PLAYERS=3 ./Scripts/atlas-gsz.sh 0-dot
```

The dedicated tentative-capture workload has six genuine ordinary operations:
three scalar multiplications alternating with three dot products. It is used
instead of `0-dot` for the focused 3- and 5-party capture checks because one
DoubleRand source group contains `n` outputs while current `0-dot` has only
four eligible ordinary operations. Ordinary and focused communication for the
dedicated workload must match exactly at the same party count.

The failure-mode families are expected to terminate nonzero after
reporting their focused PASS state and the fail-stop
`RecoveryNotImplemented` boundary. They must create no authenticated handles
and must not seal or promote the affected checkpoint.

The three Check-Tag presentation failures are distinct: `ordinary-failure`
changes sigma at a real ordinary-source contribution (using an explicit
test-only `lambda=1` override only if its sampled challenge is zero),
`base-contribution-failure` changes sigma at the BaseSharing contribution,
and `failure` changes only the final aggregate holder tag. Honest execution
always uses the sampled zero-permitted challenge without an override.

## Near-term honest-path milestones

The first segment-owned ordinary scalar/dot collector, one close-time source
authentication, one promoted checkpoint over exact handle-based
`z_t = e_t - r_t` live-outs, and the communication-neutral runtime corrections
are implemented and committed.

The immediate next milestone is not another coding pass. It is the
protocol-to-code communication audit described above. Until that audit
identifies the exact discrepancy between the restricted implementation and
GSZ20's complete Tag realization, do not add deferred operation families,
multiple logical segments, final output gating, or a new FTag design merely to
improve benchmark numbers.

After the audit is complete, the next implementation milestone must be chosen
from its findings and must remain independently reviewable. Any later source
collector work must continue to use the king's existing real-dealer batch; it
must not create a second logical dealer for the king.

## Reporting

The final report for a coding pass should include:

- initial `HEAD`;
- initial and final `git status --short`;
- files changed;
- concise summary of the real protocol behavior added;
- exact communication, randomness, and ownership changes;
- how batching and key reuse are preserved;
- failure semantics;
- exact build and test commands and results;
- `git diff --check` result;
- diffstat;
- explicit deferred limitations;
- confirmation that the optimized ultimate-tuple success path remains intact.

Do not print the full Git diff unless requested. The user will inspect the diff
separately.

Do not claim full GOD security or complete protocol support from a focused
vertical slice or opt-in test hook.
