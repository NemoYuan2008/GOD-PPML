# GOD-PPML MP-SPDZ implementation sources

This archive contains selected files from an MP-SPDZ fork used to implement
an honest-majority, n-party PPML protocol with guaranteed output delivery.

The implementation is adapted from an existing GS20/Atlas-based
malicious-with-abort PPML implementation.

## Authoritative accompanying documents

Implementation choices should remain aligned with:

1. `GOD-PPML-technical-core.zip`
2. `GOD_CONTROL_PLANE_MAP.md`
3. `GSZ20.pdf`
4. `GS20.pdf`
5. `TDSC.pdf`

The central provenance direction is:

```text
dealer-generated source batches
    -> authentication
    -> authenticated source handles
    -> public linear checkpoint derivations
```

Derived checkpoint outputs must not be authenticated as newly dealt source
sharings.

## Main files

### `AtlasGsz.h` and `AtlasGsz.hpp`

These contain the main GS20/GOD-PPML implementation, including:

- multiplication and dot-product transcript collection;
- GS20-style batched verification;
- virtual-transcript construction;
- optimized ultimate-tuple checking;
- GOD control-plane and diagnostic state;
- an opt-in real global optimistic FTag vertical slice with both a source-only
  handle-commit path and a checkpoint-coupled authentication/promotion path;
- authenticated source handles and derivation-based checkpoint promotion.

Eligible ordinary scalar-multiplication and dot-product operations now enter
one explicit logical online segment. `max_before_check` still creates internal
GS20 verification batches, but successful internal checks only transfer their
exact frozen candidates into the segment-owned collector. The collector forms
one canonical all-dealer source set, invokes source authentication exactly once
at segment close, and promotes one checkpoint over the ordered ordinary
`z_t` live-outs. This remains a one-worker, one-segment optimistic path, not a
general PPML segment scheduler or an output gate.

### `AtlasGszShare.h`

Share type and protocol wiring for the AtlasGsz protocol.

### `Atlas.h` and `Atlas.hpp`

The Atlas semi-honest baseline and related multiplication,
dot-product, and multiply-then-truncate support.

### `AtlasConfig.h`

Protocol and implementation configuration.

### Shamir and networking files

The archive includes selected modified MP-SPDZ Shamir/input/opening helpers
needed to understand the implementation.

### `Programs/`

Focused multiplication and dot-product smoke-test programs.

## Current implementation boundary

Implemented:

- existing malicious-with-abort PPML operations and verification;
- multiplication and dot-product virtual transcripts;
- optimized ultimate-tuple success opening;
- real restricted `e = 1` Check-Key;
- reusable verifier-holder `mu` keys;
- a configurable, session-immutable base-field FTag batch width `B`, with
  default `B=4` and override `ATLAS_GSZ_FTAG_CHUNK_WIDTH`; `B` is the
  paper's `ell`, and because this realization fixes `e=1`, it also equals
  `q=ell/e`. It is not an extension degree;
- internal zero padding in a partial final chunk, without creating source
  ordinals, authenticated handles, or derivation terms for padding;
- a newly and independently uniformly sampled `nu` for each
  batch/chunk/verifier/holder relation;
- real MPC tag computation and holder reconstruction;
- one global Check-Tag over the exact requested pending dealer batches for one
  source-only or checkpoint-coupled invocation, using canonical ascending
  dealer order and `position(r,k)=r*(W+1)+k`;
- one zero-permitted shared challenge, one aggregate `B`-vector, and one
  aggregate tag scalar per holder-to-verifier relation;
- one compact `ok`/smallest-failed-holder decision per verifier in one
  broadcast round, rather than one public Boolean per verifier-holder
  relation;
- atomic candidate-handle validation and batch authentication after every
  global equation passes, independently invocable without a checkpoint;
- the existing stronger checkpoint-coupled commit, which additionally
  validates checkpoint derivations and atomically seals/promotes the
  checkpoint;
- authenticated dealer-source handles;
- derivation-based checkpoint sealing and promotion;
- atomic producer-neutral `Shamir::get_randoms()` provenance for original
  unscaled dealer sources and exact public output derivations, paired across
  the degree-`t` and degree-`2t` sides of buffered Atlas DoubleRand material;
- private-process transfer of the exact shared producer record and producer
  output ordinal from each successfully completed concrete Atlas operation to
  the corresponding real AtlasGsz wrapper record;
- exact fixed-king ordinary scalar/dot special sharing `[e]^T_t`, using the
  deterministic ascending no-dispute support `T={0,...,t}` for the current
  king 0, zero local shares outside `T`, and no resharing randomness;
- one opt-in AtlasGsz-owned tentative DoubleRand capture round for completed
  ordinary scalar and dot-product wrapper records, with duplicate exact-output
  rejection, whole-source-group deduplication, and deterministic per-dealer
  aggregation of original degree-`t` local source shares;
- one exact concrete king-generated `e_t` source record per captured ordinary
  operation, validated against the retained real wrapper transcript, canonical
  support, operation result, and king-only full-vector evidence;
- candidate-local temporary derivations from tentative source references to
  each consumed `r_t`, validated against the completed transcript and dealer
  contribution decomposition, while paired degree-`2t` provenance remains
  validation/evidence only;
- atomic tentative candidate finalization, inspection, malformed-copy
  validation, and discard;
- one opt-in consuming adapter from a finalized tentative DoubleRand candidate
  to one authoritative batch per real dealer and exactly one source-only global
  authentication invocation;
- atomic ascending-dealer batch registration with one range-checked batch ID
  per dealer and a single `next_batch_id` advance for the complete set;
- a value receipt containing only public numeric batch summaries and the exact
  canonical temporary-source-reference-to-authenticated-handle mapping;
- in-adapter conversion of every captured degree-`t` `r_t` derivation into an
  ordered handle-based `LinearDerivation`, returned by value in that receipt
  only after exact authoritative-handle validation and local evaluation against
  the captured consumed share;
- one direct authenticated king-source handle per captured operation, with the
  `e_t` suffix appended only to the king's existing real-dealer batch and no
  one-term `e_t` derivation;
- one exact by-value handle-based `z_t = e_t - r_t` derivation per captured
  ordinary scalar or dot operation, ordered as `(1,h_e)` followed by the
  existing `r_t` terms with native field-negated coefficients, without a new
  source, handle, authentication invocation, checkpoint, or registry;
- segment-owned ordinary orchestration in the order
  `freeze/preflight -> internal GS20 check -> collect`, repeated across zero or
  more threshold batches, followed by exactly one
  `segment preflight -> source-only authentication -> checkpoint promotion` at
  logical segment close;
- communication-free segment preflight that preserves completed-operation
  order, rejects duplicate consumed producer outputs, deduplicates exact whole
  producer groups, and reads the concrete output count of every producer group
  instead of assuming `t+1` outputs;
- one authoritative real-dealer source sequence per party at close, with all
  concrete king `e_t` sources appended to king 0's existing DoubleRand dealer
  sequence and no synthetic second king dealer;
- the same fatal `checking_gs20` lifecycle around every nonempty GS20 batch;
  successful unsupported-only batches retire their verification evidence and
  return to idle without source authentication, while every GS20 exception
  retains failure evidence and forbids a second communicating check;
- normal verification of the real AtlasPrep mul-public batch: the existing
  independently owned preprocessing protocol branch replaces only its exact
  empty `BitPrep::set_protocol()` initialization prelude, records every real
  mul-public coordinate/transcript, and runs the existing GS20-only check;
- an explicit fixed-king-0 contract for this milestone;
- one authoritative frozen candidate per internal GS20 check, exact transfer
  into the segment collector after success, and exact post-authentication
  `r_t`/direct-`e_t`/`z_t` binding validation at segment close;
- one sealed/promoted checkpoint containing the explicitly supported ordered
  ordinary `z_t` live-out derivations, backed by retained authenticated source
  records and handles;
- successful segment cleanup that removes internal transcripts, tentative
  producer/candidate state, fresh `nu`, holder tags, the successful invocation
  presentation, and receipt-local mappings while retaining the reusable `mu`
  epoch, authenticated source batches, checkpoint, monotonic IDs, and public
  communication counters;
- invocation-local direct indexing for producer/output/source-group capture and
  FTag material lookup, without a persistent provenance registry;
- fail-stop `RecoveryNotImplemented` behavior;
- restricted `e = 1` dealer Verify-Sharing;
- restricted checked `BaseSharing` before Check-Tag mask tagging;

This is base-field chunking with `F=K=F_p` and `e=1`, not extension-field
packing.

Not yet implemented or integrated:

- more than one logical online segment or general segment-scheduler
  integration;
- complete input, truncation, or preprocessing provenance;
- input, MultTrunc, mul-public, and other deferred operation-family live-outs
  in the segment checkpoint;
- mul-public, virtual-transcript, compression-generated, and ultimate-tuple
  provenance;
- final output gating;
- real `Analyze-Sharing`;
- localization, rollback, retry, and continued execution after faults.

Source-only authentication remains an authenticated-source-table operation;
it does not itself create or promote a checkpoint. The segment owner invokes
that component once after all internal GS20 checks succeed, converts the exact
committed handles, then separately constructs and promotes the checkpoint.
GS20 failure retains the affected frozen evidence, latches the segment failure,
and performs no authentication. Authentication rejection creates neither
handles nor a checkpoint and terminates at `RecoveryNotImplemented`.

Tentative capture by itself creates no dealer batch or batch ID,
authentication invocation, authenticated handle, FTag chunk, checkpoint, or
scheduler state. The opt-in adapter consumes a finalized candidate, registers
the complete real-dealer batch set, and passes all batch IDs to the existing
source-only global path exactly once. While its stack-local claimed candidate
is still alive, it converts the tentative degree-`t` `r_t` derivations to
`LinearDerivation` values over the exact committed handles and returns them in
the value receipt. It also returns the exact public `z_t` derivation formed
from each direct authenticated `e_t` suffix handle and the corresponding
negated `r_t` derivation. The finalized DoubleRand table remains `q` sources per
dealer; the prospective king batch alone appends the `m` concrete `e_t`
sources at ordinals `q,...,q+m-1`, and the receipt returns their direct handles.
It does not create a checkpoint or persistent derivation registry.

The adapter first rejects active capture or absence of a finalized candidate
without mutation. Malformed finalized input is explicitly discarded before ID
allocation, registration, communication, or authentication randomness. After
successful preflight, the candidate is one-shot: success and authentication
rejection both consume it, and a second call returns before changing any ID,
batch, invocation, communication counter, or authentication PRNG state.

Successful authentication certifies consistency of the dealer-generated
source sharings. It does not prove that a corrupt dealer sampled a uniformly
random or otherwise prescribed secret.

The first production segment collector now merges king 0's PartialMult-dealt
degree-`t` `e_t` sources with that party's other real-dealer sources. The
collector reports the actual producer records, producer groups, outputs per
group, per-dealer source counts, chunk counts, committed handles, and an
instrumented peak estimate of collector-owned bytes.

`AtlasConfig::max_before_check` remains unchanged and counts `x_verify`
coordinates, not high-level operations. A dot product is one captured
operation and one concrete king `e_t` source even when its coordinate length
crosses or overshoots the threshold. The focused integration mode uses a
test-only effective threshold and an explicit logical-segment close after the
final residual flush. A destructor close remains only a fallback for workloads
without a scheduler hook and is not a production pre-output gate.

Authentication failures on both paths remain fail-stop at
`RecoveryNotImplemented`: no participating batch receives handles, and no
checkpoint is created, sealed, or promoted by the failed invocation.

Therefore, this is currently an implementation of the optimistic execution
path and supporting vertical slices, not a complete GOD implementation.
The deterministic support rule is only for the current optimistic no-dispute
stage; it does not claim `Corr`/`Disp`-aware selection or continued execution.

For `m` dealers and `W=max_r w_r`, the uniform global Check-Tag layout has
maximum degree at most `m*(W+1)-1`. Its concrete soundness uses
`p=2^61-1` and must be union-bounded over all verifier-holder relations and
invocations; the implementation does not claim arbitrary kappa-bit
soundness.

## Communication audit and experiment status

The communication audit is complete and frozen for the exact implemented
scope: one logical online segment, 29,696 captured ordinary scalar operations,
optimistic honest execution, restricted `F=K=F_(2^61-1)` with `e=1`, real
source authentication, authenticated handles, and one promoted checkpoint.
This is not a complete Protocol-37 or complete GOD PPML implementation.

### Correct communication comparison

`Data sent` is party-local. `Global data sent` is the sum over all parties.
The previously quoted original GS20 value `12.2587 MB` is party 0 at 15
parties; the matching original global value is `31.5270 MB`.

At the exact finite-optimal 15-party width `B=397`:

```text
original GS20 global                 31.527000 MB
pre-authentication protocol drift     1.930860 MB
authentication                       21.471240 MB
------------------------------------------------
current GOD global                   54.929100 MB
```

The current result is therefore `1.742x` the original GS20 global result, not
a comparison of `55.57 MB` against the party-0 `12.2587 MB` counter.

### Exact finite authentication formula

For one segment and one reusable key epoch:

```text
K = n(n-1)
L = K(3n-5) + (n-1)
Q = sum_d ceil(source_count_d / B)

E_V  = 6nK
E_K  = K[(n-2)B + n^2 - n + 14]
E_O  = LQ
E_BS = n[6K + t(B+4)]
E_BT = nL
E_CT = K(B+7)

authentication bytes = 8(E_V + E_K + E_O + E_BS + E_BT + E_CT)
```

The `+4` in `E_BS` is the actual 32-byte pairwise `ShamirInput` seed. Every
audited run matches this formula exactly in bytes with zero unattributed
authentication communication.

### Finite-optimal widths for `1-net-a`

| n | optimal B | Q | exact auth MB | GOD global MB | original GS20 global MB | ratio |
|---:|---:|---:|---:|---:|---:|---:|
| 3  | 320 | 186 | 0.080832 | 4.611330 | 4.287950 | 1.075x |
| 5  | 372 | 160 | 0.553600 | 9.814340 | 8.764670 | 1.120x |
| 7  | 386 | 154 | 1.766352 | 15.817000 | 13.289800 | 1.190x |
| 9  | 413 | 144 | 4.087584 | 22.961200 | 17.836500 | 1.287x |
| 11 | 387 | 154 | 7.887880 | 31.607500 | 22.395200 | 1.411x |
| 13 | 382 | 156 | 13.564512 | 42.147700 | 26.960700 | 1.563x |
| 15 | 397 | 150 | 21.471240 | 54.929100 | 31.527000 | 1.742x |

The code default `B=4` is retained for focused tests but is pathological for
large workloads. Every experiment must pass and report an explicit public
width. There is no automatic production selector.

The audit also establishes that Protocol-25 work per real
`dealer x chunk x verifier x holder` relation is genuine, and that
extension-field packing is not a missing base-field-equivalent bandwidth
optimization. The paper's `5.5+epsilon` statement ignores fixed terms
independent of the circuit; this small benchmark is outside that finite
amortization regime at larger party counts.

### Runtime status

Communication is resolved, but runtime is not yet optimized. Matched `-O3`,
no-audit, local-loopback single runs range from `7.685x` the original GS20
runtime at three parties to `9.620x` at fifteen parties. These are
characterization measurements only. The next technical milestone is repeated
measurement and profiling of the current HEAD, the last pre-authentication
control, and the original GS20 checkout before any optimization patch.

Do not reopen the already-fixed quadratic runtime regression, redesign FTag,
or remove protocol messages merely to improve these figures.

## Build and tests

Typical development/smoke-test commands from the full repository root are:

```sh
make -j6 atlas-gsz-party.x
conda run -n pytorch ./compile.py 0-dot
./Scripts/atlas-gsz.sh 0-dot
```

For matched communication or runtime experiments, use a clean optimized
build with assertions enabled, `-Werror`, and no `NDEBUG`:

```sh
make clean
make -j6 OPTIM=-O3 atlas-gsz-party.x
conda run -n pytorch ./compile.py 1-net-a

# Audited communication run
ATLAS_GSZ_FTAG_CHUNK_WIDTH=$B \
ATLAS_GSZ_COMM_AUDIT=1 \
ATLAS_GSZ_RUNTIME_AUDIT=1 \
PLAYERS=$n ./Scripts/atlas-gsz.sh 1-net-a

# Fair total-runtime run with audit overhead disabled
ATLAS_GSZ_FTAG_CHUNK_WIDTH=$B \
PLAYERS=$n ./Scripts/atlas-gsz.sh 1-net-a
```

The current repository is not `NDEBUG`-clean. Treat NDEBUG compatibility as
a separate deferred release-engineering issue; do not disable assertions for
the communication or runtime matrix.

Focused optimistic authentication tests use `ATLAS_GSZ_AUTH_TEST` as described
in `AGENTS.md`.

Focused tentative capture uses
`Programs/Source/0-tentative-double-rand-capture.py`, which alternates three
ordinary scalar multiplications with three ordinary dot products over distinct
private inputs. The dedicated workload is necessary because each DoubleRand
source group contains `n` outputs, while current `0-dot` has only four eligible
ordinary operations and therefore cannot cross a source-group boundary with
five parties. Its ordinary and focused communication counts must match at the
same party count.

The same workload also drives `ATLAS_GSZ_AUTH_TEST=special-e-t`, which checks
the six exact special sharings, their public support and private king evidence,
and malformed support rejection without capturing or authenticating `e_t`.

The same workload drives the opt-in
`tentative-double-rand-adapter-{honest,malformed,e-t-malformed,verify-failure,tag-failure}`
modes. The adapter modes exercise component integration only; they do not form
a checkpoint, integrate a scheduler, or establish complete operation or
segment provenance.

Focused segment-owned integration uses
`Programs/Source/0-honest-batch-integration.py` with 3 and 5 parties and
`ATLAS_GSZ_AUTH_TEST=honest-batch-integration`. Its companion
`honest-batch-integration-preflight-rejections`,
`honest-batch-integration-auth-rejection`, and
`honest-batch-integration-gs20-failure` modes cover communication-free exact
preflight rejection, zero authentication at seven internal ordinary GS20
checks, one close-time invocation, whole-group deduplication using the actual
producer width, king-source merging, handle/derivation/checkpoint creation,
bounded cleanup, and both ordinary fail-stop boundaries. The
`honest-batch-integration-unsupported-gs20-failure` mode proves that one real
unsupported-only batch performs exactly one GS20 invocation, starts no source
authentication, latches the fatal lifecycle, and rejects a second check with
zero additional communication. The
`honest-batch-integration-nested-preprocessing` mode demonstrates the actual
61-coordinate AtlasPrep mul-public branch at the focused workload's current
bit demand, and `honest-batch-integration-fixed-king` checks the local fixed-0
guard.

## Archive scope

This is a selected source archive rather than the complete repository. It may
omit `.git`, build products, generated files, and unrelated MP-SPDZ sources.

For convenience, this selected archive flattens some repository paths: the protocol files correspond to `Protocols/`, and the files under `Programs/` correspond to `Programs/Source/` in the full repository.
