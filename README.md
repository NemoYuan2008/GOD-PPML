# GOD-PPML MP-SPDZ implementation sources

This archive contains selected files from an MP-SPDZ fork used to implement an
honest-majority, \(n\)-party PPML protocol with guaranteed output delivery.

The implementation adapts an existing GS20/Atlas malicious-with-abort PPML
implementation toward GSZ20.

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

Derived checkpoint outputs and published failure snapshots are not new
dealer-generated sources and must not be authenticated as such.

## Current implementation

The current code implements an **optimistic honest-path vertical slice**, not a
complete GOD protocol.

For one worker and one logical online segment containing supported ordinary
scalar multiplications and dot products, it provides:

- ordinary Atlas computation and transcript capture;
- GS20 batched verification and virtual transcripts;
- exact fixed-king special sharings `[e]^T_t`;
- producer-side DoubleRand source provenance;
- one segment-owned collector across internal GS20 batches;
- one close-time global source-authentication invocation;
- authenticated source handles;
- exact handle-based `r_t` derivations;
- direct authenticated `e_t` handles;
- exact `z_t = e_t - r_t` derivations;
- one sealed and promoted checkpoint;
- fail-stop `RecoveryNotImplemented` behavior on faults.

The current path uses fixed king 0 and deterministic no-dispute support
`T={0,...,t}`. Corr/Disp-aware support selection, retry, rollback, and
continued execution after faults are not implemented.

## Accepted fixed-king runtime optimization

The code now contains an immutable `FixedKingInterpolationContext` owned by
each Atlas instance.

Its identity is:

```text
(number of parties, Shamir threshold, fixed king, ordered support T)
```

It caches only deterministic public interpolation data:

- support membership and ordering;
- special-sharing construction coefficients;
- support-basis evaluation factors;
- support reconstruction factors;
- all-party degree-\(2t\) reconstruction factors.

It does not cache shares, `e_t` values, evidence, handles, derivations, FTag
material, protocol state, or validation results. All previous validations still
execute.

The context is rebuilt when the fixed king or the current supported set is
reset. This does not claim that future Corr/Disp-aware support selection has
already been implemented.

## Source authentication

The optimistic source-authentication slice uses:

```text
F = K = F_p
p = 2^61 - 1
e = 1
```

This is base-field chunking, not extension-field packing.

It includes:

- exact dealer Verify-Sharing;
- checked transient BaseSharing;
- reusable verifier-holder `mu` keys;
- fresh per-batch/chunk/verifier/holder `nu`;
- real twisted-sharing FTag computation;
- one global all-dealer/all-batch Check-Tag identity;
- authenticated handles committed only after complete success;
- checkpoint derivations built from those committed handles.

The base-field FTag width `B` is session-immutable and defaults to `4` unless
explicitly overridden. Experiments must explicitly use the width selected for
the audited party count.

## Frozen communication result

For `Programs/Source/1-net-a`, the completed communication audit used:

- 29,696 captured ordinary operations;
- one logical segment;
- exact authentication-byte accounting;
- zero unattributed authentication communication.

Audited endpoint widths and totals:

```text
n=3:  B=320, global total 4.611330 MB
n=15: B=397, global total 54.929100 MB
```

At \(n=15\):

```text
original GS20 global                 31.527000 MB
pre-authentication protocol drift     1.930860 MB
authentication                       21.471240 MB
current GOD global                   54.929100 MB
```

The communication result is frozen unless a direct measurement error is found.

## Runtime result

Matched profiling showed that the former apparent multi-second destructor
hotspot was mostly segment-close time. True final member teardown was about
14 ms at \(n=15\).

The accepted immutable interpolation-context optimization preserved protocol
behavior, communication, provenance, handles, derivations, checkpoints, and all
validation counts.

Fair, audit-disabled `1-net-a` timing improved from:

```text
n=3:  0.437448 s -> 0.391224 s  (10.57%)
n=15: 4.201140 s -> 3.457350 s  (17.70%)
```

No further runtime optimization is currently selected.

## Main files

- `Protocols/AtlasGsz.h`, `Protocols/AtlasGsz.hpp`:
  GS20/GOD verification, source authentication, ordinary segment collection,
  handle conversion, checkpoint creation, auditing, and fail-stop behavior.
- `Protocols/Atlas.h`, `Protocols/Atlas.hpp`:
  Atlas multiplication, fixed-king special sharing and evidence, and the
  immutable public interpolation context.
- `Protocols/AtlasGszShare.h`:
  share type and protocol wiring.
- `Protocols/AtlasConfig.h`:
  protocol configuration.
- selected Shamir/input/opening helpers:
  producer provenance and supporting MP-SPDZ behavior.
- `Programs/Source/`:
  focused smoke, provenance, authentication, integration, and `1-net-a`
  workloads.

## Build and basic tests

From the full repository root:

```sh
make -j6 OPTIM=-O3 atlas-gsz-party.x

conda run -n pytorch ./compile.py 0-mul-input
./Scripts/atlas-gsz.sh 0-mul-input

conda run -n pytorch ./compile.py 0-dot
./Scripts/atlas-gsz.sh 0-dot

conda run -n pytorch ./compile.py 0-dot-input
./Scripts/atlas-gsz.sh 0-dot-input
```

Focused fixed-king and one-segment integration examples:

```sh
conda run -n pytorch ./compile.py 0-tentative-double-rand-capture
ATLAS_GSZ_AUTH_TEST=special-e-t PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-tentative-double-rand-capture

conda run -n pytorch ./compile.py 0-honest-batch-integration
ATLAS_GSZ_AUTH_TEST=honest-batch-integration PLAYERS=3 \
    ./Scripts/atlas-gsz.sh 0-honest-batch-integration
```

Compile and run `1-net-a` fairly with audit/test hooks disabled:

```sh
conda run -n pytorch ./compile.py 1-net-a

env -u ATLAS_GSZ_COMM_AUDIT \
    -u ATLAS_GSZ_RUNTIME_AUDIT \
    -u ATLAS_GSZ_MEMORY_AUDIT \
    -u ATLAS_GSZ_AUTH_TEST \
    ATLAS_GSZ_FTAG_CHUNK_WIDTH=397 PLAYERS=15 \
    ./Scripts/atlas-gsz.sh 1-net-a
```

Use `-O3`, retain `-Werror`, keep assertions enabled, and leave `NDEBUG`
undefined.

Detailed workflow, focused failure tests, frozen invariants, and coding rules
are in `AGENTS.md`.

## Not yet implemented

- more than one logical online segment;
- a general segment scheduler;
- final production output gating;
- complete input, truncation, MultTrunc, or preprocessing provenance;
- checkpoint live-outs for deferred operation families;
- mul-public and compression-generated source provenance;
- real `Analyze-Sharing`;
- Corr/Disp mutation and dispute-aware support selection;
- localization, rollback, retry, and continued execution after faults.

## Archive scope

This is a selected source archive rather than the complete repository. It may
omit `.git`, build products, generated files, and unrelated MP-SPDZ sources.

Some selected archives flatten paths: protocol files correspond to
`Protocols/`, and files under `Programs/` correspond to
`Programs/Source/` in the complete repository.
