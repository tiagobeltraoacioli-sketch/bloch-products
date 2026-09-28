# Bloch Markets Studio

Static product site, Developer Studio and Qualification Lab for inspecting local
Ustav evidence. This directory brings the published application into the product
workspace and adds a dependency-free offline inspector. It does not activate a
network, host a lifecycle API or handle keys.

## Develop and inspect

Requires Node 22 or newer; the local web server also uses Python 3. No npm
dependencies or installation step are required.

```sh
cd apps/bloch-markets
npm test
npm run dev
```

Open `http://127.0.0.1:8787/studio/` or `/lab/`. The local server binds only to
loopback. The deployment artifact is the `public/` directory. The existing
Cloudflare Pages project is `blochmarkets`; its production branch is `main`.
See the [deployment guide](docs/DEPLOYMENT.md) for preview, publication and
verification commands.
`public/_headers` preserves the CSP and browser security headers observed on the
existing site for hosts supporting that file. Python's preview server does not
apply those headers.

Inspect a collection using the same validation modules as the browser:

```sh
node scripts/inspect.mjs \
  public/studio/examples/lifecycle.json \
  public/studio/examples/native-pair.json \
  public/lab/example.json
```

The inspector accepts individual receipts, saved Studio review bundles and Lab
reports. It recomputes receipt checksums and source comparisons instead of
trusting saved assessments. Inputs are regular UTF-8 JSON files, capped at 12
files and 16 MiB combined; the existing 1 MiB individual receipt/report limits
also apply. Unix symlinks are refused. It performs no network calls or kernel
execution, and writes one JSON assessment only after all inputs validate.

| Exit | Meaning |
| --- | --- |
| `0` | Valid structure, matching source claims, and every included qualification case reported as passed |
| `2` | Valid structure with a source mismatch or a reported failed/ignored case; details remain inspectable |
| `1` | Invalid evidence, incorrect usage or unreadable input; no partial assessment is emitted |

For a JSON-only npm invocation, use `npm --silent run inspect -- FILE.json`.
A successful inspection is not a signed run attestation or production approval.

## Recovery provenance and upstream source

The baseline was downloaded from `https://blochmarkets.xyz/` on 2026-09-28.
[`docs/recovered-public-manifest.json`](docs/recovered-public-manifest.json)
records the original URL, byte count and SHA-256 of each of the 26 public files.
These are retrieval checksums, not signatures or an original Git history.
The site source and its Python runners were not found in the available GitHub
repositories or cached branch histories during the account review.

The baseline reference contract remains pinned to protocol revision
`2da509438542c72d1f9bb2ca7437798e2a9b21ab`. Cargo.lock, both example sources and
all three integration-test source hashes were independently compared with that
Git object. Retained receipt/report bytes are unchanged. Their claimed Rust
execution was not rerun during this recovery.

Intentional changes to recovered public assets:

- `lab/model.mjs`: require an actual string outcome. Previously `["passed"]`
  passed the membership check through JavaScript coercion, but vanished from
  the strict string comparisons used to total results. Eight accepted cases
  could therefore produce a seven-case summary. Arrays and nested arrays now
  fail before workspace replacement; valid passed/failed/ignored strings remain
  inspectable.
- `index.html` and `status.json`: identify the dormant canonical native candidate
  separately from the older reference examples and production capability.
- All three HTML pages: remove the Cloudflare-injected analytics script from
  recovered response bytes. Removing that script reproduces the original HTML
  hashes from the previous Cloudflare deployment; the host manages injection.
- Studio and Lab pages/guides: identify the original runner checkout requirement
  and document the independent offline inspector in this workspace.

The published planners still reference the original `sandbox/run.py` and
`sandbox/qualify.py`. Those scripts were not recovered and are not
included here. Their displayed commands require the original Markets runner
checkout; do not interpret this recovered frontend as a complete runner package.
The new inspector works independently of those runners. Upstream Cargo examples
and tests can be run directly in their exact pinned protocol checkout, but their
raw output is not automatically a Studio receipt.
The corresponding public `/sandbox/` URLs returned HTML rather than Python or
the requested JSON pin during the recovery check.

## Validation

`npm test` exercises the original public examples, source-pin agreement,
strict outcome types, failed/ignored reports, source differences, review checksum
tampering, bounded local file reads and CLI exit behavior. The regression was
reproduced before the fix: four invalid-array cases failed their rejection tests;
the complete suite passes after the fix.

The GitHub workflow runs the same tests and the three-example CLI inspection.
Browser rendering, a fresh Rust qualification run and hosted deployment are
separate checks; they are not claimed by the Node test suite.

See the [development map](../../docs/BLOCH-MARKETS-DEVELOPMENT.md) for the larger
architecture and the next integration steps.
