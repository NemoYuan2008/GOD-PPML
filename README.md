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

The optimistic FTag slice is currently exercised through a focused test hook.
It is not yet integrated into the normal PPML segment scheduler.

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
- one opt-in AtlasGsz-owned tentative DoubleRand capture round for completed
  ordinary scalar and dot-product wrapper records, with duplicate exact-output
  rejection, whole-source-group deduplication, and deterministic per-dealer
  aggregation of original degree-`t` local source shares;
- candidate-local temporary derivations from tentative source references to
  each consumed `r_t`, validated against the completed transcript and dealer
  contribution decomposition, while paired degree-`2t` provenance remains
  validation/evidence only;
- atomic tentative candidate finalization, inspection, malformed-copy
  validation, and discard;
- fail-stop `RecoveryNotImplemented` behavior;
- restricted `e = 1` dealer Verify-Sharing;
- restricted checked `BaseSharing` before Check-Tag mask tagging;

This is base-field chunking with `F=K=F_p` and `e=1`, not extension-field
packing.

Not yet implemented or integrated:

- normal segment-scheduler integration;
- an independently reviewed adapter/integration decision from the finalized
  tentative candidate to real authentication and Check-Tag;
- real `Analyze-Sharing`;
- localization, rollback, retry, and continued execution after faults.

Source-only authentication is an authenticated-source-table operation, not a
checkpoint: it creates no checkpoint record and performs no sealing or
promotion. The tentative candidate creates no dealer batch or batch ID,
authentication invocation, authenticated handle, FTag chunk, checkpoint, or
scheduler state. It is not converted to the existing handle-based
`LinearDerivation` and is not passed to either global authentication path. The
next provenance step may be a separately reviewed adapter from the finalized
candidate to the source-only path, not automatic production Check-Tag wiring.

Authentication failures on both paths remain fail-stop at
`RecoveryNotImplemented`: no participating batch receives handles, and no
checkpoint is created, sealed, or promoted by the failed invocation.

Therefore, this is currently an implementation of the optimistic execution
path and supporting vertical slices, not a complete GOD implementation.

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

## Archive scope

This is a selected source archive rather than the complete repository. It may
omit `.git`, build products, generated files, and unrelated MP-SPDZ sources.

For convenience, this selected archive flattens some repository paths: the protocol files correspond to `Protocols/`, and the files under `Programs/` correspond to `Programs/Source/` in the full repository.
