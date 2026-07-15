# AGENTS.md

## Project context

This repository is an MP-SPDZ fork used to implement an honest-majority,
\(n\)-party privacy-preserving machine-learning protocol with guaranteed output
delivery (GOD). It adapts the existing GS20/Atlas malicious-with-abort PPML
implementation toward the GSZ20 construction.

The main implementation files are:

- `Protocols/AtlasGsz.h`
- `Protocols/AtlasGsz.hpp`
- `Protocols/Atlas.h`
- `Protocols/Atlas.hpp`

Related files may include:

- `Protocols/AtlasGszShare.h`
- `Protocols/AtlasConfig.h`
- `Protocols/Shamir.h`
- `Protocols/Shamir.hpp`
- `Protocols/ShamirInput.h`
- `Protocols/ShamirInput.hpp`
- `Programs/Source/0-mul-input.py`
- `Programs/Source/0-dot.py`
- `Programs/Source/0-dot-input.py`
- `Programs/Source/0-tentative-double-rand-capture.py`
- `Programs/Source/0-honest-batch-integration.py`
- `Programs/Source/1-net-a.py`

Do not add a separate protocol implementation or broadly refactor unrelated
MP-SPDZ code unless the current milestone explicitly requires it.

The local reference locations are:

- GSZ20 paper: `~/papers/GSZ20.pdf`
- GOD-PPML LaTeX technical core: `~/papers/GOD-PPML-paper`

## Source-of-truth hierarchy

When implementation choices affect terminology, protocol structure, ownership,
batching, state transitions, or security claims, use this hierarchy:

1. the current GOD-PPML LaTeX technical core;
2. `GOD_CONTROL_PLANE_MAP.md`, the paper-to-code architecture contract;
3. GSZ20 for the concrete GOD/FTag realization where the technical core is
   abstract;
4. GS20 and the existing TDSC implementation for the underlying
   malicious-with-abort PPML machinery;
5. existing C++ metadata, which is an implementation inventory rather than an
   independent semantic specification.

Do not silently choose an answer for an issue marked unresolved in the
technical core or control-plane contract. Report the ambiguity.

## Current project status

The repository currently implements an **optimistic honest-path vertical
slice**, not a complete GOD protocol.

The implemented production path covers one worker and one logical online
segment containing supported ordinary scalar multiplications and dot products.
It performs:

1. ordinary Atlas computation;
2. transcript and source-provenance capture;
3. internal GS20 batch verification;
4. segment-owned collection of successful frozen batches;
5. one close-time global source authentication;
6. authenticated-handle conversion;
7. construction of exact public `r_t`, direct `e_t`, and
   `z_t = e_t - r_t` bindings;
8. one checkpoint candidate;
9. checkpoint sealing and promotion;
10. fail-stop termination if a required check rejects.

This is an implementation of the optimistic execution path of the GOD
protocol, including segment verification and one authenticated checkpoint. It
must not be described as a complete GOD implementation.

### Development freeze

The communication-efficiency audit is complete, resolved, documented, and
frozen. The residual-runtime profiling milestone is also complete, and the
first measured runtime optimization—the immutable fixed-king interpolation
context—has been accepted.

Do not reopen any of the following unless a direct measurement or correctness
error is demonstrated:

- FTag-width optimization;
- communication formulas or attribution;
- logical segment count used by the completed audit;
- the former quadratic authenticated-handle lookup regression;
- the false “multi-second final destructor” hypothesis;
- broad runtime instrumentation without a new, narrowly defined question.

Do not propose or implement another optimization merely because adjacent code
looks inefficient. A new optimization milestone requires a measured dominant
cause, a narrow safety argument, and explicit authorization.

## Stage strategy

### Stage 1: optimistic honest execution

Stage 1 prioritizes real computation and communication on the path followed
when all parties behave honestly. Operations that always execute in an honest
run must not be represented only by metadata because their communication and
runtime are part of the experiments.

The current Stage-1 implementation is intentionally narrower than the final
paper design. It supports one ordinary scalar/dot segment and one promoted
checkpoint, but not normal continuation through multiple logical segments or
final output gating.

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

Until Stage 2 exists, failures in the Stage-1 path are fail-stop:

1. retain a clear failure class and relevant diagnostics;
2. create no authenticated handles for a failed batch;
3. do not seal or promote the affected checkpoint;
4. do not clear the failure state;
5. terminate with `RecoveryNotImplemented` or the repository equivalent;
6. do not claim that recovery, rollback, or `Analyze-Sharing` succeeded.

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
- do not authenticate a published failure snapshot after failure;
- do not create handles from rejected, tentative, or merely planned
  authentication;
- `VShare.Analyze` must eventually consume existing authenticated handles plus
  a public derivation and submitted claims;
- `VShare.Analyze` must not manufacture new authenticated sources.

A stable source handle is semantically:

```text
(batch_id, dealer_id, source_ordinal)
```

Successful authentication certifies consistency of dealer-generated source
sharings. It does not prove that a corrupt dealer sampled a uniformly random or
otherwise externally prescribed secret.

## Current implementation boundary

### GS20 and virtual-transcript machinery

The repository contains working GS20/Atlas verification machinery, including:

- scalar multiplication and dot-product transcript collection;
- de-linearization;
- dimension reduction;
- recursion and randomization;
- virtual-transcript and fixed-king evidence propagation;
- the optimized ultimate-tuple success opening;
- failure evidence sufficient for the current fail-stop boundary.

Virtual transcripts and fixed-king evidence are required by the GSZ20
fault-localization architecture. They must not be removed merely to reduce
runtime.

### Producer provenance and ordinary source capture

`Shamir::get_randoms()` exposes atomic producer provenance containing original
unscaled dealer sources and exact public output derivations. Atlas pairs the
degree-\(t\) and degree-\(2t\) records for buffered DoubleRand material.

Each completed eligible Atlas scalar or dot operation exposes:

- the consumed producer record;
- the consumed producer-output ordinal;
- the exact partial-multiplication transcript;
- the fixed king;
- the public special-sharing support;
- king-only full-vector evidence where applicable.

AtlasGsz captures this information into tentative ordinary candidates. Paired
degree-\(2t\) provenance remains validation/evidence only; it is not
authenticated as a degree-\(t\) source.

### Fixed-king special sharing

For the current optimistic no-dispute path:

- the fixed king is party 0;
- \(T=\{0,\ldots,t\}\) in canonical numeric order;
- the special sharing `[e]^T_t` is zero outside \(T\);
- construction consumes no fresh randomness;
- the king retains the exact full distributed vector as private evidence.

This is a Stage-1 deterministic support rule. It does **not** implement
`Corr`/`Disp`-aware support selection or continued execution after the dispute
state changes.

### Immutable fixed-king interpolation context

The accepted runtime optimization introduces an immutable
`FixedKingInterpolationContext` owned by each `Atlas` instance.

Its exact public identity is:

```text
(number of parties, Shamir threshold, fixed king, ordered support T)
```

The standard evaluation-point mapping is `party + 1`; the existing Shamir
helper uses public point `-1` to represent zero.

The context may contain only deterministic public interpolation data:

- the ordered support and support-membership table;
- special-sharing construction points and coefficients;
- the support-basis evaluation matrix;
- support reconstruction factors;
- all-party degree-\(2t\) reconstruction factors.

The context must never contain:

- secret shares;
- concrete operation-specific `e_t` values;
- transcripts or king evidence;
- authenticated handles or derivations;
- FTag keys, masks, or tags;
- a cached “validation succeeded” result;
- any protocol-state transition.

All existing validation calls remain mandatory. Reuse of interpolation factors
must not reduce support/order, degree, reconstruction, represented-secret,
local-binding, concrete-`e_t`, producer, candidate, frozen-batch, checkpoint,
derivation, or handle validation counts.

The context is rebuilt by `set_fixed_king()` or
`set_fixed_king_special_sharing_support()`. Construction of the replacement
context must complete before it becomes active. Do not claim that
Corr/Disp-aware invalidation has been implemented: future dispute-aware support
selection must explicitly pass the new supported configuration through the
setter and must be designed as a Stage-2 milestone.

Do not replace this instance-owned immutable context with a process-global
mutable cache.

### Global optimistic source authentication

The repository contains a real global optimistic FTag source-authentication
slice with:

- authoritative ordered dealer-source batches;
- restricted \(e=1\) dealer Verify-Sharing over each exact unpadded source
  batch;
- restricted \(e=1\) consistency checking for each transient BaseSharing;
- a configurable, session-immutable base-field FTag width `B`, defaulting
  to `4` unless explicitly overridden;
- one reusable verifier-holder `mu` key epoch;
- restricted \(e=1\) Check-Key with a fresh public-protocol mask;
- a fresh independent `nu` for every batch/chunk/verifier/holder relation;
- real twisted-sharing tag computation;
- holder-only tag reconstruction;
- one global all-dealer/all-batch Check-Tag identity;
- canonical ascending dealer order;
- the uniform exponent layout
  `position(r,k) = r * (W + 1) + k`;
- one checked BaseSharing contribution at `k=0`;
- only real source chunks at `k=1,...,w_r`;
- one aggregate `B`-vector and one aggregate tag scalar per
  holder-to-verifier relation;
- one compact Protocol-27 decision per verifier;
- atomic source-handle publication only after global success.

This implementation is restricted to:

```text
F = K = F_p
p = 2^61 - 1
e = 1
```

It is base-field chunking, not extension-field packing.

The source-only authentication path commits authenticated source handles and
does not itself create a checkpoint. The segment owner separately converts
handles, builds checkpoint derivations, validates them, and promotes the
checkpoint.

### Ordinary one-segment integration

Eligible ordinary scalar and dot operations follow:

```text
freeze/preflight
    -> internal GS20 check
    -> collect successful frozen batch
    -> repeat as needed
    -> logical segment close
    -> one source-only authentication invocation
    -> handle conversion and binding validation
    -> one checkpoint candidate
    -> seal and promote
```

`AtlasConfig::max_before_check` remains an internal GS20
memory/verification boundary. It counts `x_verify` coordinates rather than
high-level operations. One dot product is one captured operation and one
concrete king `e_t` source even when its coordinate length crosses or
overshoots the threshold.

The segment collector:

- preserves completed-operation order;
- rejects duplicate consumed producer outputs;
- deduplicates exact whole producer groups;
- reads each producer group’s actual output count;
- constructs one authoritative real-dealer source sequence per party;
- appends concrete king `e_t` sources to king 0’s existing real-dealer batch;
- never creates a second logical dealer or synthetic dealer for the king.

After authentication success, the implementation validates:

- every committed source handle;
- every `r_t` derivation;
- every direct `e_t` handle;
- every `z_t = e_t - r_t` derivation;
- the exact checkpoint candidate.

The checkpoint is sealed and promoted only after all required validations
succeed.

### Cleanup and retained state

Successful close removes transient state such as:

- internal verification transcripts;
- tentative producer/candidate state;
- successful frozen batch owners;
- fresh `nu`;
- holder tags;
- invocation-local presentations;
- receipt-local mappings.

It retains:

- authenticated dealer batches and source handles;
- the promoted checkpoint and its public derivations;
- the reusable checked `mu` epoch;
- the agreed FTag width;
- monotonic IDs and PRNG state;
- cumulative public communication counters.

The true post-close owned-member teardown is small and is not an optimization
target.

### Unsupported and deferred operation families

Unsupported operation families remain GS20-only and force an eligible ordinary
batch boundary before entering.

Not yet implemented or integrated:

- more than one logical online segment;
- a general segment scheduler;
- final output gating;
- complete input provenance;
- complete truncation/MultTrunc provenance;
- checkpoint live-outs for deferred operation families;
- mul-public source provenance and live-outs;
- virtual-transcript-, compression-, or ultimate-tuple-generated source
  provenance;
- real `Analyze-Sharing`;
- localization, rollback, retry, and continued execution after faults.

The real AtlasPrep mul-public branch is verified through the existing GS20-only
path, but it is not authenticated into the ordinary segment checkpoint.

Legacy authentication, recovery, and Analyze metadata skeletons remain in the
code. They are not authoritative production provenance. Do not build new
cryptographic execution on an incorrect legacy abstraction merely to minimize
a diff.

## Frozen communication audit

The completed communication audit used `Programs/Source/1-net-a` with:

- 29,696 captured ordinary scalar operations;
- one logical segment;
- \(F=K=\mathbb F_{2^{61}-1}\);
- \(e=1\);
- finite-optimal FTag width chosen separately for each party count;
- exact authentication-byte accounting;
- zero unattributed authentication communication;
- comparison against the original GS20 repository.

For the audited endpoint widths:

```text
n=3:  B=320
n=15: B=397
```

At \(n=15\):

```text
original GS20 global                 31.527000 MB
pre-authentication protocol drift     1.930860 MB
authentication                       21.471240 MB
current GOD global                   54.929100 MB
```

The identity

```text
31.527000 + 1.930860 + 21.471240 = 54.929100 MB
```

is the accepted global reconciliation.

The current audited global totals are:

```text
n=3:  4.611330 MB
n=15: 54.929100 MB
```

At \(n=15\), authentication is exactly 21,471,240 bytes. The audit reports zero
unattributed authentication communication.

Do not confuse party-0 communication with global communication. Do not reopen
the communication result unless runtime or correctness work reveals a direct
measurement error.

## Runtime profiling and accepted optimization

### Profiling conclusion

The matched profiling comparison used:

- original GS20 commit
  `6d7bc9bdd81b6088e5ebe18eed02db6c83c9588c`;
- pre-authentication GOD commit
  `8bfd3006eaea92ce9773e42d8e5521f6bfc5f8f6`;
- current pre-optimization GOD implementation commit
  `cc9cd574b3e0ec495c8d5864bce15d663b643f4a`.

The old quadratic authenticated-handle lookup regression did not recur:
audited runs recorded zero linear-search comparisons.

The apparent multi-second `AtlasGsz` destructor hotspot was inclusive time
from the destructor invoking segment close. True final owned-member teardown
was about 14 ms at \(n=15\) and is not a runtime target.

The remaining overhead was traced primarily to repeated fixed-king public
interpolation-factor construction and repeated use of those factors in
evidence/candidate paths, with non-king parties waiting at existing exchanges
and challenges for king-side local work.

### Accepted immutable-context optimization

The accepted optimization precomputes only the invariant public fixed-king
interpolation data described above. It preserves all validation calls,
communication, randomness, protocol state, source provenance, handle counts,
derivation counts, checkpoint counts, and the ultimate-tuple opening.

For `1-net-a`, party-0 audited validation counts remained:

```text
fixed-sharing constructions                 29,808
fixed-evidence validations                  29,808
capture-time concrete-e_t validations       29,696
all concrete-e_t validations                89,088
candidate validations                            8
exact batch-correspondence validations           4
candidate finalizations/freezes                  4 / 4
integrated closes                                1
linear handle-search comparisons                 0
contexts constructed                             1
context reuses                             178,680
```

Accepted diagnostic reductions at \(n=15\) included:

```text
fixed-sharing construction       163.452 ms -> 12.123 ms
fixed-evidence validation        226.420 ms -> 28.678 ms
capture concrete-e_t validation  296.176 ms -> 12.074 ms
frozen-batch construction        225.591 ms -> 44.782 ms
integrated close                1305.026 ms -> 1080.601 ms
```

The accepted fair, audit-disabled comparison was:

```text
n=3:  0.437448 s -> 0.391224 s  (10.57% improvement)
n=15: 4.201140 s -> 3.457350 s  (17.70% improvement)
```

These values compare the unmodified pre-optimization current implementation
against the optimized working tree in one matched experiment matrix. Do not
combine them arithmetically with timings from a different profiling matrix.

The remaining runtime cost is distributed. Candidate finalization and
integrated close remain substantial, but no further optimization is currently
authorized.

## Critical implementation constraints

### Preserve the optimized ultimate-tuple opening

Do not undo the optimized ultimate-tuple success path.

It must:

1. use `malicious_mc.POpen()` to open only `(alpha, beta, gamma)`;
2. return immediately when `alpha * beta == gamma`;
3. call `broadcast_local_shares(ultimate_tuple)` only after the optimized check
   fails.

Do not restore unconditional publication of the complete virtual transcript.

### Preserve role ownership

Production state must respect protocol ownership:

- verifier \(P_v\) owns clear long-term `mu_(v->i)`;
- verifier \(P_v\) owns freshly sampled per-batch/chunk `nu`;
- holder \(P_i\) owns the reconstructed tag;
- non-holder parties retain only local twisted shares needed for MPC;
- ordinary production records must not co-locate clear `mu`, clear `nu`,
  holder tag, and holder source-share vectors.

Test-only diagnostics must be narrowly scoped and must not print or retain
private authentication material.

### Preserve key reuse and batching

- Reuse one `mu_(v->i)` vector across batches and successful segments in the
  same key epoch.
- Never regenerate `mu` per wire, source, dealer batch, checkpoint, or segment
  unless a later explicitly specified key-rotation rule requires it.
- Independently sample fresh `nu` for every authenticated dealer-batch chunk
  and applicable verifier-holder relation.
- Accidental equality between independent `nu` samples is allowed.
- Authentication must scale with source-batch chunks, not with
  `wire x verifier x holder`.
- Do not call the current optimistic no-dispute slice the complete GSZ20 `TAG`
  protocol.
- For `m` dealers and `W=max_r w_r`, the global Check-Tag polynomial has
  maximum degree at most `m*(W+1)-1`.
- Concrete soundness uses \(p=2^{61}-1\) and must be union-bounded over all
  verifier-holder relations and invocations. Do not claim arbitrary
  \(\kappa\)-bit soundness.

### Communication and randomness discipline

Do not add production communication, openings, broadcasts, exchanges,
send/receive operations, or randomness unless the milestone explicitly
requires them.

When new communication is authorized:

- use normal MP-SPDZ networking/accounting paths;
- preserve message ordering;
- explain ownership and destination of each message class;
- ensure the cost appears in communication measurements;
- avoid debug broadcasts that reveal private values;
- keep failure-only publication off the honest path.

Avoid new uses of the following unless explicitly justified:

- `POpen`
- `Broadcast_Receive`
- `Check_Broadcast`
- `exchange`
- direct `send` / `receive`
- `get_random` or new PRNG streams

### State and architecture discipline

- Prefer one authoritative record plus small transient results.
- Use IDs and references rather than copying the same identity graph into
  multiple stores.
- Do not add another metadata-only
  plan/readiness/attempt/receipt pipeline without real execution need.
- A checkpoint ID does not imply sealing.
- Seal only after every referenced derivation resolves to authenticated source
  handles and all required checks succeed.
- Failed, pending, or incomplete checkpoints remain unsealed and unpromoted.
- Do not mix logical-segment identity with retry-attempt identity in new code.
- Do not clear retained failure evidence merely to make a later check pass.
- Do not bypass a validation merely because the same invariant was validated at
  an earlier ownership boundary.
- Do not cache validation results in the interpolation context.

### Build configuration

Production comparisons must use:

- `-O3`;
- assertions enabled;
- `-Werror` retained;
- `NDEBUG` undefined.

Do not define `NDEBUG`. A prior experiment showed that doing so changed
runtime behavior and caused input-reading failure. That issue is deferred and
is not part of the current baseline.

Audit modes must be disabled for fair experiment timing.

## Workflow rules

Before editing, run:

```sh
git status --short
git rev-parse HEAD
```

If the working tree is not clean, stop and report unless the milestone
explicitly says to continue from the current patch.

Never reset, stash, discard, stage, unstage, commit, amend, clean, or rewrite
history unless explicitly instructed.

Before changing code:

1. inspect the relevant current implementation;
2. identify the exact paper procedure being realized;
3. state which existing helpers will be reused;
4. state what communication and randomness will change;
5. state the expected failure semantics;
6. give a concise implementation plan.

Prefer small, reviewable, milestone-sized diffs. Modify only files permitted by
the milestone. Explain before touching an additional file.

Do not commit changes unless explicitly asked.

## Build and test rules

After editing, run at least:

```sh
git diff --check
make -j6 OPTIM=-O3 atlas-gsz-party.x
```

If staged changes exist, also run:

```sh
git diff --cached --check
```

Compile again when switching test programs because `compile.py` overwrites the
active program artifacts.

### Ordinary smoke tests

```sh
conda run -n pytorch ./compile.py 0-mul-input
./Scripts/atlas-gsz.sh 0-mul-input

conda run -n pytorch ./compile.py 0-dot
./Scripts/atlas-gsz.sh 0-dot

conda run -n pytorch ./compile.py 0-dot-input
./Scripts/atlas-gsz.sh 0-dot-input
```

Expected `0-mul-input` output:

```text
63
143
396
```

Expected `0-dot` and `0-dot-input` output, allowing tiny fixed-point drift:

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

Use the repository-supported party-count convention, for example:

```sh
./Scripts/atlas-gsz.sh -N 5 0-dot
```

or:

```sh
PLAYERS=5 ./Scripts/atlas-gsz.sh 0-dot
```

### Focused fixed-king and provenance tests

```sh
conda run -n pytorch ./compile.py 0-tentative-double-rand-capture

ATLAS_GSZ_AUTH_TEST=special-e-t PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=special-e-t PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture

ATLAS_GSZ_AUTH_TEST=tentative-double-rand-capture PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-capture PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture

ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-honest PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=tentative-double-rand-adapter-honest PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture
```

The dedicated capture workload contains three scalar multiplications alternating
with three dot products over distinct private inputs.

### Focused one-segment integration tests

```sh
conda run -n pytorch ./compile.py 0-honest-batch-integration

ATLAS_GSZ_AUTH_TEST=honest-batch-integration PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration

ATLAS_GSZ_AUTH_TEST=honest-batch-integration-fixed-king PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration-fixed-king PLAYERS=5 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
```

The broader focused family also includes:

- `honest-batch-integration-preflight-rejections`;
- `honest-batch-integration-auth-rejection`;
- `honest-batch-integration-gs20-failure`;
- `honest-batch-integration-unsupported-gs20-failure`;
- `honest-batch-integration-nested-preprocessing`;
- tentative-adapter malformed and failure modes;
- source-only and checkpoint-coupled Verify-Sharing, BaseSharing, Check-Tag,
  omission, duplicate, and epoch-mismatch tests.

Expected failure modes terminate nonzero after reporting the focused PASS state
and the fail-stop `RecoveryNotImplemented` boundary. They must create no
authenticated handles and must not seal or promote the affected checkpoint.

### `1-net-a` correctness and experiment run

Compile:

```sh
conda run -n pytorch ./compile.py 1-net-a
```

Run with all audit/test hooks disabled. Examples:

```sh
env -u ATLAS_GSZ_COMM_AUDIT \
    -u ATLAS_GSZ_RUNTIME_AUDIT \
    -u ATLAS_GSZ_MEMORY_AUDIT \
    -u ATLAS_GSZ_AUTH_TEST \
    ATLAS_GSZ_FTAG_CHUNK_WIDTH=320 PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 1-net-a

env -u ATLAS_GSZ_COMM_AUDIT \
    -u ATLAS_GSZ_RUNTIME_AUDIT \
    -u ATLAS_GSZ_MEMORY_AUDIT \
    -u ATLAS_GSZ_AUTH_TEST \
    ATLAS_GSZ_FTAG_CHUNK_WIDTH=397 PLAYERS=15 \
    ./Scripts/atlas-gsz.sh 1-net-a
```

### Audit modes

Communication audit:

```sh
ATLAS_GSZ_COMM_AUDIT=1 \
ATLAS_GSZ_FTAG_CHUNK_WIDTH=397 \
PLAYERS=15 ./Scripts/atlas-gsz.sh 1-net-a
```

Runtime audit:

```sh
ATLAS_GSZ_RUNTIME_AUDIT=1 \
ATLAS_GSZ_FTAG_CHUNK_WIDTH=397 \
PLAYERS=15 ./Scripts/atlas-gsz.sh 1-net-a
```

Audit output is diagnostic only. Do not use audit-enabled total runtime as the
fair performance result.

Runtime-audit reporting may include only public timings, counts, sizes, and
configuration. It must not print shares, keys, masks, tags, or other private
authentication material.

## Near-term milestones

The current implementation and the accepted interpolation-context optimization
may be frozen for experiments.

No further runtime optimization is the default next step. If the user later
authorizes another measured optimization, candidate finalization and
owned-derivation construction are the remaining profiled areas, but they must
be split into a narrow safe cause before modification.

If protocol development resumes, the expected Stage-1 sequence is:

1. add deferred operation-family provenance and checkpoint live-outs;
2. integrate continuation across more than one logical segment;
3. implement final production output gating;
4. only then begin explicitly scoped Stage-2 recovery work.

The next milestone must continue to use the king’s existing real-dealer batch;
it must not create a second logical dealer for the king.

Keep each milestone independently reviewable. Do not pull later work into an
earlier pass merely because adjacent code is available.

## Reporting

A coding-pass report must include:

- initial `HEAD`;
- initial and final `git status --short`;
- files changed;
- concise summary of real protocol behavior changed;
- exact communication and randomness changes;
- ownership and lifetime changes;
- batching and key-reuse preservation;
- validation-count preservation where relevant;
- failure semantics;
- exact build and test commands and results;
- fair timing methodology for performance changes;
- `git diff --check` result;
- diffstat;
- explicit deferred limitations;
- confirmation that the optimized ultimate-tuple path remains intact;
- confirmation that nothing was staged or committed unless explicitly asked.

Do not print the full Git diff unless requested. The user will inspect it
separately.

Do not claim full GOD security or complete protocol support from a focused
vertical slice, one-segment honest path, or opt-in test hook.
