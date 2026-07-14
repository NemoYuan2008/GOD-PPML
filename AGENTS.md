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
- production semantic output gating and normal processor-boundary
  finalization.

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
  extension-field packing;
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

Eligible ordinary scalar-multiplication and ordinary dot-product verification
batches are now integrated automatically through the existing
`AtlasConfig::max_before_check` / `maybe_check()` / `check()` lifecycle. The
production order is pure finalize/freeze and exact preflight, then the existing
GS20 verification, then exactly one source-only global authentication
invocation. One frozen candidate is retained across GS20. Only after GS20 and
authentication both succeed are the exact `r_t`, direct `e_t`, and `z_t`
bindings validated and the batch-local verification, capture, receipt, dealer
batch, `nu`, holder-tag, and global-invocation state retired. Reusable checked
`mu` keys, their epoch, agreed FTag width, monotonic IDs, PRNG state, and
cumulative counters persist.

Unsupported operation families remain GS20-only and force an eligible ordinary
batch boundary before entering. `max_before_check` still counts `x_verify`
coordinates rather than operations, so a single dot product can cross or
overshoot it while producing one captured operation and one concrete king
`e_t` source. Focused integration tests use a test-only effective threshold
and explicit residual flush.

Independently owned AtlasGsz preprocessing protocols now have one explicit,
synchronous pre-consumption release boundary. `BitPrep` holds the persistent
branch used by AtlasPrep bits, inverses, inputs, inherited squares, daBits, and
loose edaBit vectors; the temporary triple generator owns the other reachable
branch. Each generator keeps new values in a local vector, calls
`before_preprocessing_release()` after all finalizers, and only then moves the
values into the consumer-visible owner buffer. Mul-public remains
unsupported/noneligible and GS20-only. Ordinary scalar work retains the
existing eligible source-authentication behavior. A fatal release leaves the
new values unpublished and rejects later release attempts without
communication.

`AtlasGsz::~AtlasGsz()` is non-throwing and communication-free. `BitPrep` does
not invoke destructor-time `check()` for protocols exposing the explicit
release API. Main online-protocol checking remains owned by the processor/tape
`Proc.check()` path.

The production runtime now has an optimistic, fail-stop Stage-1 semantic
output boundary owned by the exact local prime AtlasGsz instance:

- prime public `OPEN` gates before opening communication;
- prime `PRIVATEOUTPUT` gates before mask acquisition, secret copying, or
  output preparation;
- every nonempty residual runs the existing GS20 verification, and an eligible
  ordinary scalar/dot residual then runs exactly one existing source-only
  authentication invocation;
- the exact `r_t`, direct `e_t`, and derived `z_t` bindings and successful
  batch-local cleanup are validated before output proceeds;
- retained degree-`2t` openings are checked after residual verification;
- an empty gate performs zero communication, randomness, GS20 checks,
  authentication invocations, and challenges;
- direct prime/GF2N share printing, secret sockets, explicit share-file output,
  and `Machine::run_function` are rejected before secret access, packing,
  persistence, or host transfer;
- AtlasGsz arithmetic-to-GC `SPLIT` is unsupported: `AtlasGszShare` has no
  usable `split()`, `ShareInterface::has_split` is false, and its generic
  fallback throws. The runtime rejects fail-closed before reading or copying
  the prime secret or reaching that fallback. Do not classify this conversion
  as implemented mixed-circuit support;
- GC and GF2N secret reveal remain unsupported for Stage 1 and are rejected
  before their reveal/opening operations. Already-clear output is not gated
  again;
- exactly one online arithmetic worker is supported. `CALL_TAPE` and
  sequential tapes on worker 0 remain supported;
- normal processor/tape `Proc.check()` boundaries finalize residual
  verification and then retained openings, including no-output programs;
- automatic `Machine::run` memory serialization is internal per-party
  persistence, not an authenticated checkpoint or Stage-1 recovery/restart
  mechanism;
- AtlasGsz destruction remains non-throwing and communication-free.

Any gate, GS20, authentication, binding, or retained-opening failure is fatal
and fail-stop. A second output attempt performs no further verification,
authentication, challenges, or communication. There are no checkpoints from
this lifecycle, recovery, rollback, replay, relay, retry, `Analyze-Sharing`,
localization, `Corr`/`Disp` mutation, or multi-worker execution. This is the
optimistic Stage-1 path, not complete GOD.

This automatic ordinary-batch lifecycle is not a complete segment/checkpoint
scheduler and must not be described as the complete GSZ20 authentication path.

The following honest-path items remain unimplemented:

1. complete segment-wide source collection across the deferred operation
   families, checkpoint derivation construction, and checkpoint creation;
2. normal segment/checkpoint scheduler integration beyond eligible ordinary
   GS20 verification batches;
3. integration of the existing runtime semantic output boundary with that
   future segment/checkpoint scheduler and sealed checkpoints.

Truncation, mul-public, virtual-transcript, compression-generated, and
ultimate-tuple provenance remain deferred.

A future production segment collector must merge the king's
PartialMult-dealt degree-`t` `e_t` sources with that same real party's other
dealer sources. It must not create a second logical dealer for the king.

Legacy authentication, recovery, and Analyze-related metadata skeletons remain
in the code. They are not authoritative production provenance. Do not build
new cryptographic execution on an incorrect legacy abstraction merely to
minimize a diff.

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

Focused preprocessing-release hooks (run every variant with both party
counts; the compile argument becomes part of the schedule name):

```sh
conda run -n pytorch ./compile.py 0-preprocessing-release persistent
ATLAS_GSZ_AUTH_TEST=preprocessing-release-persistent PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-preprocessing-release-persistent -b 4
ATLAS_GSZ_AUTH_TEST=preprocessing-release-persistent PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-preprocessing-release-persistent -b 4

conda run -n pytorch ./compile.py 0-preprocessing-release new-batch
ATLAS_GSZ_AUTH_TEST=preprocessing-release-new-batch PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-preprocessing-release-new-batch -b 2
ATLAS_GSZ_AUTH_TEST=preprocessing-release-new-batch PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-preprocessing-release-new-batch -b 2
```

Repeat the same compile/run pattern for `empty`, `temporary`,
`temporary-empty`, `square`, `dabit`, `edabit`, `retained-opening`, and
`gs20-failure`, using the matching `preprocessing-release-*` environment mode.
The GS20 failure run must terminate nonzero after its focused PASS line and
must not print
`PREPROCESSING_RELEASE_APPLICATION_SUCCESS`.

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

The focused conversion of captured tentative `r_t` derivations, direct
authentication of exact concrete king-generated `e_t` sources, and exact
handle-based `z_t = e_t - r_t` derivations are implemented in both the
one-shot adapter and the automatic eligible ordinary-batch lifecycle. Unless
the user changes priorities, the expected next sequence is:

1. form complete segment source collections and checkpoint derivations, then
   integrate authentication, sealing, and promotion;
2. integrate normal segment continuation and connect the existing runtime
   semantic output boundary to scheduler-sealed checkpoints.

The next milestone must continue to use the king's existing real-dealer batch;
it must not create a second logical dealer for the king.

Keep each milestone independently reviewable. Do not pull later milestones
into an earlier pass merely because adjacent code is available.

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
