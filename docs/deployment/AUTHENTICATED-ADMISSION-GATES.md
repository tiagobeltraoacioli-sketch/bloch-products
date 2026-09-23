# Authenticated local-state admission gates

## Status and scope

This is a production-gate specification, not deployment evidence. The remote
cursor protocol, memory-only fetch session, local coordination, semantic
admission, transition/recovery composition, single-host CAS reference core and
re-bootstrap tools exist as building blocks. Audience-bound threshold trusted
time, fresh bounded acquisition, a single-host monotonic-boundary reference
store and bounded cursor ingress also exist. A qualified network transport,
independent rollback-resistant time root, replicated remote service, authority
signing boundary and production systemd composition are not deployed or
qualified.

The existing `bloch-products-synthetic-store-check@.service` is
**synthetic-only**. It checks a locally staged root with the generic store
verifier. It does not authenticate
a remote cursor observation, prove freshness, coordinate a writer or perform
Bloch Data/Bloch Pay semantic restoration. It has no install relationship and
must remain excluded from every production target; it never satisfies these
gates.

## Fixed host layout

Numeric UIDs/GIDs must be allocated once and recorded in the host change
record. Accounts must be locked, have no login shell and run no unrelated code.

| Purpose | Account | Path | Ownership/mode |
|---|---|---|---|
| Data state | `bloch-data` | `/var/lib/bloch-products/data/state` | `bloch-data:bloch-data`, `0700` |
| Data cursor | `bloch-data` | `/var/lib/bloch-products/data/cursor` | `bloch-data:bloch-data`, `0700` |
| Data coordination | `bloch-data` | `/run/bloch-products/data/coord` | `bloch-data:bloch-data`, `0700` |
| Data trusted-time boundary | `bloch-data` | `/var/lib/bloch-products/data/trusted-time-boundary` | explicitly provisioned store, `0700` |
| Pay state | `bloch-pay` | `/var/lib/bloch-products/pay/state` | `bloch-pay:bloch-pay`, `0700` |
| Pay cursor | `bloch-pay` | `/var/lib/bloch-products/pay/cursor` | `bloch-pay:bloch-pay`, `0700` |
| Pay coordination | `bloch-pay` | `/run/bloch-products/pay/coord` | `bloch-pay:bloch-pay`, `0700` |
| Pay trusted-time boundary | `bloch-pay` | `/var/lib/bloch-products/pay/trusted-time-boundary` | explicitly provisioned store, `0700` |
| Fetch staging | `bloch-data-fetch` / `bloch-pay-fetch` | `/run/bloch-products-fetch/INSTANCE` | matching fetch UID, `0700`, ephemeral |
| Pinned trust material | root | `/etc/bloch-products/trust/INSTANCE` | `root:root`, directory `0500`, files `0400` |

The fetch accounts may use the network but must have no access to state, cursor
or coordination directories. Product accounts may access only their own three
paths and must have no network during admission. Coordination directories must
be pre-created; a missing or different path is an error, never permission to
create an alternative lock domain.

Every cooperating local admission and writer must acquire the same coordination
lock before time-boundary, cursor or state locks, always in this order:

```text
coordination -> trusted-time boundary -> cursor -> state
```

Advisory locks do not constrain code running as the same UID that ignores the
protocol. Dedicated UIDs are therefore part of the security boundary.

## Proposed split-unit architecture

This section is a deployment design, not an implemented unit chain. The
current `bloch-local-state-runtime` keeps nonce generation, fetch verification
and admission in one process while holding the local lock; it does not by
itself satisfy the separate fetch/product UID and network-isolation model
below. Production qualification must select and test one complete composition
without reducing nonce, trusted-time or policy provenance to an unauthenticated
raw cursor.

The runtime's fresh-time entry points load the explicitly provisioned boundary,
acquire and verify a nonce-bound token, durably advance the boundary, and only
then authenticate the remote cursor and local state. Creating an empty boundary
directory through tmpfiles is forbidden because it could blur deletion from
first provisioning. Every cooperating boundary updater must use the same local
coordination domain.

### 1. Networked fetch unit

`bloch-products-cursor-fetch@INSTANCE.service` runs as the matching fetch UID.
For every admission attempt it must:

1. start with a newly created empty runtime directory;
2. generate a 256-bit CSPRNG nonce for this invocation and never reuse it;
3. fetch the signed remote cursor observation and all referenced checkpoint and
   semantic artifacts through the qualified authenticated transport;
4. enforce a bounded request deadline using a monotonic clock;
5. publish a bounded create-only runtime bundle; and
6. exit unsuccessfully if any fetch is partial, ambiguous or stale.

The fetcher is not trusted to declare the cursor valid. Its output remains
untrusted until the offline admission unit verifies signatures, pins, nonce,
time and exact artifact relationships. It must not retain a persistent success
cache. A fresh activation, nonce and invocation record are required for every
admission. Runtime output is removed after consumption, including on failure.

### 2. Offline admission unit

`bloch-products-authenticated-admission@INSTANCE.service` runs as
`bloch-INSTANCE`, has `PrivateNetwork=yes`, and requires a successful fresh
fetch unit. It must re-verify the complete signed observation in-process before
using its cursor. Passing only the extracted raw cursor between units is not
sufficient because it loses nonce, freshness and policy provenance.

The admission sequence, under the fixed coordination lock, is:

1. authenticate the remote policy against its independently provisioned pin;
2. verify the observation threshold, exact nonce, instance identity and trusted
   current time;
3. authenticate the exact retained checkpoint and require equality with the
   observed remote cursor and local cursor;
4. load state using the complete checkpoint root;
5. verify the cursor-bound semantic manifest and product policy;
6. run Data lifecycle or Pay adjustment semantic restoration;
7. recheck local cursor and state before returning success; and
8. destroy the ephemeral fetch credentials.

The unit is silent on success and never logs state, nonce, regulated payloads or
credentials. Fetch failure, missing credentials, time uncertainty, stale
runtime output or any mismatch rejects startup. There is no local fallback.

## Exact credential set

The admission unit accepts only these fixed systemd credential names; arbitrary
files below `$CREDENTIALS_DIRECTORY` and ordinary owner-private trust inputs are
not production inputs.

| Credential | Required | Provenance |
|---|---|---|
| `remote-observation` | Data and Pay | Fresh fetch result; threshold-signed |
| `request-nonce` | Data and Pay | Generated for the same fetch invocation |
| `fetch-invocation` | Data and Pay | Future fetch-client gate; current admission CLI does not consume it |
| `remote-policy` | Data and Pay | Reviewed trust ceremony |
| `remote-policy-pin` | Data and Pay | Separate authenticated release/control record |
| `trusted-time-token` | Data and Pay | Fresh nonce-bound threshold-signed interval for the exact state and remote policy |
| `trusted-time-request-nonce` | Data and Pay | Fresh CSPRNG nonce for the same time-token acquisition |
| `trusted-time-policy` | Data and Pay | Reviewed time-authority ceremony, audience-bound to state and remote policy |
| `trusted-time-policy-pin` | Data and Pay | Separate authenticated release/control record |
| `checkpoint-artifact` | Data and Pay | Exact artifact referenced by observed cursor |
| `checkpoint-policy` | Data and Pay | Exact policy referenced by observed cursor |
| `semantic-manifest` | Data and Pay | Exact digest referenced by observed cursor/checkpoint |
| `lifecycle-policy` | Data only | Exact digest referenced by Data semantic manifest |
| `expected-state-identity` | Data and Pay | Fixed instance/tenant deployment record |

The current systemd-mode admission CLI does not consume the four trusted-time
credentials and is therefore not this production composition. The names above
reserve the exact reviewed interface for a future qualified unit.

Credentials must be bounded, regular, single-link systemd credential objects
with the reviewed root ownership/mode for the deployed systemd version. Exact
names, not merely parent-directory membership, must be enforced. Checkpoint and
semantic pins are accepted only after the remote observation is authenticated;
they must not be derived from an unverified raw cursor. The remote policy pin
must never arrive in the same untrusted fetch response as the policy.

## Nonce and trusted-time gates

- A nonce belongs to one fetch invocation and one state identity.
- The signed observation must contain that exact nonce.
- Copying a nonce/observation pair from a prior invocation or boot is rejected.
- The split offline `nonce` and `verify` commands are ceremony/debug tools, not
  by themselves a production freshness mechanism.
- Production verification must not accept operator-supplied `--evaluated-at`.
  It reads current time internally or verifies an independently signed trusted
  time token.
- The fetch round trip is bounded with a monotonic clock. Wall time is still
  required for policy effective/expiry intervals and must be qualified.
- The unit starts only after the approved time-synchronization gate. Neither
  `ProtectClock=yes` nor a local NTP status flag alone attests correct time.

Maximum accepted clock skew, observation age and network deadline must be
specified in the change record and tested at both boundaries.

## Remote CAS and recovery contract

Production writers remain disabled until a qualified remote service provides
durable, linearizable compare-and-swap. The repository's Unix reference core
demonstrates serialized durable single-host behavior, but is neither a
replicated service nor a signing authority. A request contains the exact old cursor digest,
exact canonical successor cursor, state identity and an idempotency/transaction
ID. The service allows create-once absent-to-generation-zero bootstrap, exactly
one-generation advancement and exact idempotent replay. It returns a signed
success or conflict receipt containing the authoritative current cursor. TLS,
service identity, authority/HSM separation, storage durability, backup and HA
must be independently qualified.

The only permitted write order, under the local coordination lock, is:

1. fetch and authenticate the authoritative current cursor;
2. require exact equality with local cursor/state and validate the product
   transition;
3. `prepare_state` and durably fsync `pending.json`;
4. obtain the threshold checkpoint over the exact candidate and semantic
   manifest;
5. remote CAS old-to-new using the stable transaction ID;
6. fetch/verify the accepted successor or signed CAS receipt;
7. advance the local cursor exactly;
8. promote the exact pending state; and
9. reload and semantically restore before reporting readiness.

Recovery is determined only by authenticated remote state:

| Crash point | Required recovery |
|---|---|
| Before remote CAS | Keep old current; discard pending only after authenticated evidence that CAS did not accept it |
| CAS accepted, local cursor old | Re-fetch accepted cursor, advance local cursor, then promote exact pending |
| Local cursor advanced, state old | Promote only matching pending; missing/conflicting pending fails closed |
| State promoted, response lost | Exact retry is idempotent; re-fetch and re-run full semantic admission |
| Semantic restore fails after promotion | Keep service offline; do not locally roll back an authoritative remote cursor |
| CAS conflict | Verify signed current cursor; never promote or synthesize the rejected candidate |

Deleting a local cursor, reconstructing expectations from `state.json`, or
calling generation-zero bootstrap after prior use is forbidden.

## Re-bootstrap boundary

`bloch-local-state-rebootstrap` is an offline maintenance tool, never a systemd
startup step. It supports only checkpoint/cursor v1 evidence that already pins
a complete state-root v2. It requires new authority signatures over checkpoint
v2, independent old/new cursor digests, exact root continuity and no checkpoint
policy rotation.

Before use, all writers are externally fenced. After create-only output, the
independent control plane must compare its digest and a reviewed procedure must
install checkpoint and cursor consistently before full admission. Root v1,
policy rotation, missing lineage, locally derived pins or changed root/state
require a separate authority-approved recovery or re-genesis ceremony.

## Production gate status

| Priority | Gate | Current status | Required evidence |
|---|---|---|---|
| P0 | Admission verifies signed remote observation, nonce and independent policy pin | **Partial** | Library composition and negative tests exist; qualified transport/systemd integration evidence remains |
| P0 | Trusted time cannot be supplied by operator argument | **Partial** | Fresh audience-bound threshold acquisition and a single-host monotonic store exist; independent anti-rollback root, suspend/resume qualification and host tests remain |
| P0 | Durable linearizable remote CAS and create-once bootstrap | **Partial** | Single-host reference core, exact threshold caller authorization and concurrency tests exist; replicated service, fresh challenge service, external decision signing and operational qualification remain |
| P0 | One orchestrated writer/recovery path holds coordination throughout | **Partial** | Library composition and 13 crash/recovery cases exist; process/power fault injection and target-host evidence remain |
| P0 | Synthetic unit cannot satisfy a production target | **Partial** | Unit is explicitly renamed, has no install relationship and CI rejects production-target dependencies/aliases; target-host composition evidence remains |
| P1 | Fixed UIDs, paths, quotas and dedicated coordination directory | **Partial** | tmpfiles declarations exist; host manifest, unit verification and ownership checks remain |
| P1 | Exact credential names and provenance | **Partial** | Fixed CLI credential names exist; systemd integration tests and arbitrary-name rejection remain |
| P1 | Fresh fetch lifecycle with no stale runtime fallback | **Partial** | Memory-only session and bounded-ingress tests exist; qualified adapter, repeated-start, reboot and transport-failure evidence remain |
| P1 | Explicit Data/Pay state-identity mapping | **Partial** | Library cross-identity tests exist; deployed cross-product/cross-tenant evidence remains |
| P1 | Re-bootstrap maintenance and installation runbook | **Partial** | Fencing/install drill and independently retained evidence |

No P0 gate is currently closed. DEX/bridge/payment or regulated-data activation
must not rely on this admission path until every applicable P0 and P1 gate has
reviewed evidence.

## systemd and integration test plan

Run these tests on the target Linux/systemd version, not only in unit tests:

1. `systemd-analyze verify` every fetch, admission, target, tmpfiles and sandbox
   definition; unknown directives fail the release.
2. Start admission with each credential missing, renamed, duplicated,
   oversized, wrong-mode, symlinked, hardlinked and from mixed generations.
3. Prove fetch failure prevents admission and that a previous runtime bundle is
   never used on a second start or after reboot.
4. Replay a prior nonce/observation pair, including with wall-clock rollback;
   admission must fail. Test future time, maximum skew and expiry boundaries.
5. Run two remote CAS clients with the same predecessor; exactly one candidate
   wins. Retry the winner with the same transaction ID and recover after a lost
   response.
6. Inject process/power failure before and after every pending fsync, remote CAS,
   local cursor fsync, promotion rename/fsync and semantic restore.
7. Remove or misconfigure the coordination directory and prove startup refuses
   rather than creating a second lock. Prove real cross-process contention and
   consistent lock ordering.
8. Run Data and Pay under their actual UIDs. Verify neither can read or mutate
   the other's state, cursor, runtime or coordination paths; the fetch UIDs can
   access none of them.
9. Present Data credentials to Pay and vice versa, plus a valid artifact for an
   unexpected tenant identity; all must fail before state becomes ready.
10. Verify admission has no network, emits no state/credential data to stdout or
    journal, stays within CPU/memory/task/file limits and leaves AuxPoW, k3s,
    pool/proxy and G4 services unchanged.
11. Prove the synthetic unit cannot satisfy, alias or be depended
    upon by the production admission target.
12. Exercise the re-bootstrap refusal cases and an offline fenced recovery drill
    without deriving either cursor pin from the recovered host.
