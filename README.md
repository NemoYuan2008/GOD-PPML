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
- a configurable, session-immutable base-field FTag chunk width `B`, with
  default `B=4` and focused override `ATLAS_GSZ_FTAG_CHUNK_WIDTH`;
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

## Build and tests

Typical commands from the full repository root are:

```sh
make -j6 atlas-gsz-party.x
conda run -n pytorch ./compile.py 0-dot
./Scripts/atlas-gsz.sh 0-dot
```

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
