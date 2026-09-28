# Bloch Markets Qualification Lab

The Lab inspects unsigned reports from three fixed upstream integration suites: `crypto_kernel`, `native_pairs_crypto`, and `native_pool_crypto`. The published example was produced by actual offline Rust execution against the clean revision and toolchain in `catalog.json`. The eight named tests use the upstream public test fixtures, not production keys.

## Read the graph

The graph links the pinned source, each suite, and every named test. Select a node or a case-list button to inspect the test's expected assertions and open its pinned source. Filter by suite, reported outcome or text. Zoom with the graph controls and drag its background to pan. With the graph focused, arrow keys pan, +/− zoom, and Home fits the graph. The case list provides the same selection without graph gestures. A passing negative test means that its expected rejection assertion succeeded; it does not mean the invalid operation was accepted.

The local suites exercise real hybrid authorization, malformed key and signature rejection, a complete local asset lifecycle, joint pair authorization, replay rejection, atomic rollback, custody requirements, and the local pool prototype's reserve locks and position ownership. The pool test does not activate a native AMM on the network.

## Import, compare and export

A report must contain all three suites and all eight expected tests exactly once. The browser checks the local-only boundary, counts, exit codes, bounded durations, and ten source metadata comparisons. A source mismatch or a consistently recorded failed/ignored outcome remains inspectable. A missing case, contradictory summary, duplicate suite or activation claim is rejected without replacing the current report.

Files are limited to 1 MiB and stay in browser memory. Keep the current report as a baseline, or import a separate baseline, then open a new current report. The comparison lists outcome changes and source claim changes. Original JSON, coverage CSV and comparison JSON exports are explicit. Clearing the workspace removes both in-memory reports; downloaded files are unaffected.

The published example's bytes are checked against its SHA-256 in the source catalog. Uploaded reports have no run signature. Matching source claims and output hashes cannot prove execution authenticity. Saved output hashes can be compared with independently retained logs, but raw logs are not bundled. Wall times include compilation and Cargo overhead and must not be interpreted as comparable benchmarks.

## Reproduce a local qualification

The command template requires the original sandbox runner checkout. The
recovered application in `bloch-products/apps/bloch-markets` does not include
`sandbox/qualify.py` or `sandbox/protocol-pin.json`. From the original runner
checkout:

```sh
python3 sandbox/qualify.py --protocol-repo ../blochmarkets-protocol --output local-qualification.json
```

Use a clean protocol checkout at the exact revision in `sandbox/protocol-pin.json`, the pinned Rust toolchain and cached dependencies. The runner uses `cargo test --offline --locked` with one test thread and named pretty output. It checks the protocol source before and after the run, reconciles every named result with the Rust harness summary, and hashes stdout/stderr without publishing their contents.

The output filename must be new. Exit zero means every named case passed; exit two means a complete report contains a failed or ignored case; exit one means the runner could not produce a complete consistent report. A timeout, build failure, missing result or source change does not become a passing report.

To regenerate the published example and catalog after review, supply a fresh output filename and add `--publish-example`. This actually executes all three suites and writes their source and artifact hashes. The browser's command planner does not execute commands or accept keys.

## Inspect reports offline

With Node 22+, the recovered application can inspect existing reports without
the runner. From `bloch-products/apps/bloch-markets`:

```sh
node scripts/inspect.mjs public/lab/example.json
```

Use your own report filename to recompute the same source comparisons and named
outcome checks as the browser. The command writes JSON; exit 0 means matching
source claims and all reported cases passed, exit 2 means a source mismatch or
failed/ignored case, and exit 1 means invalid input. It does not run Cargo or
verify an execution signature. See the [Studio guide](../studio/GUIDE.md) for
mixed receipt/report inspection and input limits.

## Boundaries

Qualification here concerns the pinned local reference kernel. It is not a security audit, signed execution attestation, live chain transaction, hosted asset service, asset-backing claim, or production-finality evidence. Runtime network observations are available separately in Bloch Ops.
