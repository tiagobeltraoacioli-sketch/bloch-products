# Bloch Markets development map — 2026-09-28

## Review scope

The account `tiagobeltraoacioli-sketch` contains 11 repositories: ten with code
and the empty `carbonstone-real-state`. This review inventoried their committed
trees, root documentation, component boundaries and relevant development
branches. GitHub head references were checked through the authenticated API;
the newer Graphus branch was fetched before review. This is an architecture and
integration review, not a claim that every source line or every test was audited.

Default branches alone do not describe the available development work. In
particular, the Ustav reference, canonical native candidate, wallet integration
and EVM fee/custody changes live on distinct branches. A branch head or a passing
local test is not evidence of a live deployment.

## Repository responsibilities

| Repository | Inspected source and role | Consequence for Markets |
| --- | --- | --- |
| `bloch-sis-pow` | `main` at `b2298330`: Genesis-4 node and consensus. Ustav reference at `2da50943`; canonical native candidate at `8fa9ee19`. | Reuse the native ledger, cryptography and operation formats at an explicit revision. Do not confuse the Studio reference pin with the candidate or mainnet. |
| `bloch-products` | `main` at `8bd8055`: 49 Rust packages for Verify, indexing/delivery, data governance, reconciliation, state storage and route assessment. `products/portfolio.json` already lists Markets proof-ledger and lifecycle/DvP/PvP work. | Appropriate product workspace for the recovered Studio and later service adapters. Shared components are not an already hosted Markets API. |
| `postern-dex` | `main` at `65824237`; development at `e4701137` and `0c81c0ab`: Solidity V2 AMM, lens/router, asset issuance, staged deployment evidence, pool fee policies and rebates. | EVM execution is a separate adapter. These contracts cannot be substituted for native Ustav settlement or advertised as native PQ authorization. |
| `bloch-l2-evm` | `main` at `40cf04df`; fee/checkpoint development at `2ffba3ce`: revm state transition, signed Ethereum ingress, witnesses and remaining RPC/prover stubs. | EVM compatibility is available as code, with separate integration/qualification requirements. |
| `bloch-l2-bridge` | `main` at `4c480647`; Chameleon branch and later custody development at `d69c65a1`: native/ERC-20 roundtrip, bounded observers and custody configuration. | Route identity, backing, finality and external release must be qualified independently. The trusted local Chameleon checkpoint fixture is not a production finality verifier. |
| `postern-wallet` | `main` at `46f11ba3`; `codex/multichain-wallet` at `d6ef9d74`: PQ native signing, typed native laboratory client, EVM workspaces and recovery state. | Reuse typed operation review and ownership checks in future flows. Wallet discovery is not authority to execute a trade. |
| `bloch-explorer` | `main` at `5bd4492b`; development at `fc1e3735`: governed observation RPC, historical/indexer views and explicit optional native gateway methods. | Chain observations and native feature activation are different facts. Native asset indexing needs a defined event contract. |
| `bloch-inc-porb` | `main` at `82b43dc8`; Graphus development at `53fa8e71`: chain samples, Graphus/Atlas, private observation reports, portal and Ops. | Optional data/reporting integration. Private labels, customer data and scores do not enter Markets consensus or public evidence by default. |
| `blochprotocol-dev` | `main` at `edf6d1c1`: static developer portal and integration reference. | Documentation entry point; descriptions must be reconciled with the exact chosen node branch. |
| `BlochAI` | `main` at `ddba2a23`: Python inference coordinator, worker and separate BAI prototype ledger. | No required dependency for asset execution or receipt inspection. Local uncommitted AI work was left untouched. |
| `carbonstone-real-state` | No commits. | No reusable implementation identified. |

## Two native baselines

The [published Markets contract](../apps/bloch-markets/public/studio/contract.json)
uses [Ustav at `2da50943`](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/tree/2da509438542c72d1f9bb2ca7437798e2a9b21ab/crates/bloch-ustav).
Its two receipt scenarios and eight named qualification cases describe that
exact local reference kernel. Its `BlochVerifier` checks ML-DSA-65 and
Falcon-1024 together. Native pairs require joint authorization; the separate
Supply-only token pool prototype seals reserves and PQ-owned positions.

The [native candidate at `8fa9ee19`](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/blob/8fa9ee1991fccf587ebdc63b08fb9e8ff0469d11/crates/bloch-pos-committee/docs/native-consensus-integration-status.md)
is further advanced. It includes canonical dispatch for sponsored transfers,
bootstrap, gateway import/withdrawal and BLCH/native pool operations; bounded
snapshots; restart/reorg work; and owner-scoped wallet read/build RPCs. All six
production activation epochs remain `u64::MAX`. Laboratory execution uses its
own explicit feature and domain. The [candidate RPC contract](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/blob/8fa9ee1991fccf587ebdc63b08fb9e8ff0469d11/crates/bloch-pos-node/NATIVE-WALLET-RPC.md)
distinguishes trusted host projections from finality proofs.

Therefore, rebuilding snapshots, a first pool adapter or the native wallet RPC
from scratch is not the next Markets task. Qualify and integrate the existing
candidate against a defined product contract. Do not change the Studio pin to
that branch while retaining examples and tests from the old revision.

## Current increment

`apps/bloch-markets` now contains the recovered static application, with its
original retrieval manifest, the imported-outcome correction and an offline
inspector that reuses the browser validators. The inspector consumes existing
receipt/review/report formats; it does not reinterpret them as live chain events.
The local site now identifies the native candidate separately. Production
capabilities remain false and existing sample bytes/source pins remain intact.

The site was not found in the available GitHub trees or cached object paths.
Its recovery is explicitly recorded rather than presented as original history.
The original Python sandbox runners remain unavailable in this checkout.

## Next implementation sequence

1. Recover or reconstruct the original bounded sandbox runners and prove fresh
   output parity with the retained schemas. Retain stdout/stderr hashes and
   verify exact source, toolchain and lockfile before and after execution.
2. Add a separate qualification profile for `8fa9ee19` or its reviewed successor.
   Include canonical block execution, dormant-gate refusal, restart/reorg and
   wallet projection evidence; preserve the old reference profile for comparison.
3. Define a versioned Markets lifecycle/event read contract around the chosen
   native adapter. Reuse Products indexing and delivery only after field,
   ordering, identity and rollback semantics are specified.
4. Connect the selected wallet and observation surfaces in a local/test setting
   using their existing typed intents and exact network/source identities.
5. Treat any hosted pilot, activation, external custody or liquidity rollout as
   a separate concrete release with its source/finality/operational evidence.

No chain transaction, gate change, contract deployment or external message was
performed by this development increment.
