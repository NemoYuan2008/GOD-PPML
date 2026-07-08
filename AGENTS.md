# AGENTS.md

## Project context

This repository is an MP-SPDZ fork used for implementing a GOD-secure,
honest-majority, n-party PPML protocol by adapting the existing GS20/Atlas-based
implementation.

The main implementation files for the GOD/GSZ20 adaptation are usually:

- `Protocols/AtlasGsz.h`
- `Protocols/AtlasGsz.hpp`

Some earlier PPML/Atlas changes may also involve:

- `Protocols/Atlas.h`
- `Protocols/Atlas.hpp`
- `Protocols/Shamir.h`
- `Protocols/Shamir.hpp`

Do not add a separate protocol implementation unless explicitly requested.

## Workflow rules

Before editing, run:

```sh
git status --short
git rev-parse HEAD
````

If the working tree is not clean, stop and report. Do not reset, stash, discard,
or commit changes unless explicitly instructed.

Prefer small, reviewable diffs. Modify only the files named in the user’s
milestone prompt.

After editing, run:

```sh
git diff --check
make -j6 atlas-gsz-party.x
```

When requested, also run the honest tests in both 3-party and 5-party settings:

* `0-mul-input`
* `0-dot`
* `0-dot-input`

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

To run the tests, use:

```sh
conda run -n pytorch ./compile.py 0-dot-input
./Scripts/atlas-gsz.sh 0-dot-input # omitting -N defaults to 3 parties 
./Scripts/atlas-gsz.sh -N 5 0-dot-input # for 5 parties
```

Note that `./compile.py`-ing a test case will overwrite a previous program's input,
so be sure to compile when switching cases.

## Critical implementation constraints

Do not undo the optimized ultimate tuple opening cleanup.

The honest success path of the ultimate tuple check must:

1. use `malicious_mc.POpen()` to open only `(alpha,beta,gamma)`;
2. return immediately if `alpha * beta == gamma`;
3. call `broadcast_local_shares(ultimate_tuple)` only after the optimized check fails.

Do not add new production communication, opening, broadcast, exchange,
send/receive, or randomness calls unless the user explicitly asks for them.

In particular, avoid adding new uses of:

* `POpen`
* `Broadcast_Receive`
* `Check_Broadcast`
* `exchange`
* `send` / `receive`
* `get_random`

unless they already existed and are unrelated to the current milestone.

## Current boundary

Many GOD-related components are currently metadata/diagnostic skeletons only.
Do not implement real protocol behavior unless explicitly requested.

Do not implement or wire in the following unless the milestone prompt explicitly
asks for it:

* real `VShare` / `FTag`;
* authentication-key sampling;
* tag generation;
* tag verification communication;
* real Analyze-Sharing execution;
* Localize;
* Active-Dealer;
* Corrupted-Dealer;
* segment rollback/restart/re-evaluation;
* active-party filtering in real protocol execution;
* relay communication;
* production randomness or communication for authentication;
* majority-driven Corr/Disp updates;
* real segment retry;
* real GOD control-flow wiring into multiplication/check/online execution.

## Reporting

Final reports should include:

* initial HEAD;
* final `git status --short`;
* files changed;
* concise summary of changes;
* confirmation that no forbidden real protocol behavior was added;
* confirmation that no new production communication/open/randomness calls were added;
* confirmation that the optimized ultimate tuple opening remains intact;
* build/test results.

Do not paste a huge diff unless requested.
