# Admission on the occupied 8 GB AuxPoW node

## Scope

This is a fail-closed installation **plan**, not evidence that the node has been
changed. It admits canonical Bloch Data or Bloch Pay local state without
automatically stopping or modifying k3s, AuxPoW, pool/proxy or G4 forwarding.
The supplied systemd unit is an admission oneshot, not a product daemon.

Do not install until an operator has captured the current service inventory,
ports, mounts, memory pressure, disk pressure, restart policy and rollback
procedure. Genesis 3 is not targeted by this plan.

## Artifacts and trust boundaries

- Build `bloch-local-state-store` from a reviewed commit with `--locked`.
- Transfer the binary and record its SHA-256 through an authenticated channel.
- Retain each canonical root independently from its state directory. The root
  file is not secret, but its authenticity and freshness are security-critical.
  The `/etc` file is only a staged **plain** credential copy, not authenticated
  production evidence. The authoritative root and its digest must remain in the
  authenticated off-host change record.
- Do not place private keys, regulated records, credentials or tokens in the
  environment file, approval marker, unit or journal.
- The local store does not encrypt data at rest. Do not admit regulated payloads
  until host/disk encryption and the applicable retention policy are approved.

Expected executable path:

```text
/usr/local/libexec/bloch-products/bloch-local-state-store
```

Expected verification contract:

```text
bloch-local-state-store verify --store STATE_DIR --root INDEPENDENT_ROOT
```

Success is exit 0 with no output. Invalid arguments, root or store fail closed.
Verification may create or update `.state.lock` while taking its bounded local
lock; it does not rewrite the canonical state envelope. The unit therefore has
write access only to its own per-product store, never to the other product.

This bundle does not integrate `bloch-local-state-checkpoint` and has no remote
monotonic cursor. It cannot independently prove that a staged root is current or
prevent a privileged operator from staging an older matching root and state.
It is not production/root-authenticated admission. Before every pilot check, an
operator must compare the staged root digest and generation with the current,
authenticated off-host record.

The unit filename is retained for compatibility, but its description now calls
it a **synthetic storage-only check**. It must not be used as a dependency of a
production target and cannot substitute for the remote-observation,
coordination, checkpoint and semantic admission chain described in
`REMOTE-CURSOR-OPERATIONS.md`.

## Read-only host survey

Run these individually and retain the output in the change ticket. They do not
change the host:

```sh
uname -a
free -k
df -Pk
systemctl --failed --no-pager
systemctl list-units --type=service --state=running --no-pager
ss -lntup
```

Identify the actual unit names for k3s, AuxPoW, pool/proxy and G4. The preflight
reports several common names but this list is not proof of a complete inventory.

## Reviewed installation plan

The following actions are intentionally manual. Do not combine them with a
command that stops or restarts an existing service.

1. Create locked `bloch-data` and `bloch-pay` system accounts with no login
   shell. Do not share ownership between their state directories.
2. Install the reviewed binary, `deploy/preflight.sh` and
   `deploy/credential-preflight.sh` below
   `/usr/local/libexec/bloch-products`. Keep them root-owned and not group/other
   writable. Verify the recorded binary SHA-256 before proceeding.
3. Review `deploy/systemd/bloch-products.tmpfiles.conf`, then create only the
   selected instance directory with mode 0700 and owner `bloch-data` for Data or
   `bloch-pay` for Pay.
4. Copy one example environment to `/etc/bloch-products/INSTANCE.env`, keep it
   root-owned with mode 0600, replace `BLOCH_CLI_SHA256` with the
   authenticated lowercase digest, and review every path/threshold.
5. Stage a plain copy of the current authoritative canonical root at
   `/etc/bloch-products/roots/INSTANCE.root.json`, root-owned, single-link and
   mode 0400. Compare its digest and generation with the authenticated off-host
   record; do not derive it from the local store being tested. systemd copies
   this source into its protected credential directory for the unprivileged
   verifier. On the qualified systemd 255 host this appears root/root, mode
   0440, single-link and readable through systemd's credential mount. A separate
   preflight requires exactly those metadata and size bounds as the
   unprivileged user, without printing its contents.
6. After the inventory and coexistence review, create a root-owned, single-link,
   mode-0400 marker containing exactly `APPROVED_INSTANCE=INSTANCE` and one
   trailing newline.
7. Install the unit, run `systemd-analyze verify` on it, and reload systemd.
   `LoadCredential=` requires systemd 247 or later; an older or unrecognized
   directive rejects this plan rather than authorizing a less isolated fallback.
8. Run the preflight directly with the same environment, then start
   `bloch-products-admission@INSTANCE.service`. Inspect its exit status and
   journal. A failure is a rejection; do not bypass it.
9. Recheck all pre-existing services, listeners, memory and disk. Any regression
   rejects deployment and uses the reviewed rollback procedure.

The supplied profile admits synthetic pilot data only. It does not authorize
personal, financial, banking, exchange or other regulated payloads. The unit
cannot access public TCP/IP and explicitly hides common k3s, containerd and
Docker sockets. CPU, memory, tasks, file size and I/O weight are bounded.

The unit's `+` prefix intentionally runs only the host preflight as root so it
can inspect root-owned sources. That prefix bypasses the unit's `User=`/`Group=`
identity and some privilege restrictions. The fixed preflight file and every
parent directory must therefore be root-owned and not group/other writable.
The verifier and credential preflight run as the dedicated product user.

Enabling the unit is neither needed nor recommended: it performs a point-in-time
admission. A successful check does not authorize a writer, network service,
production traffic, regulated-data ingestion, custody or settlement.

## Rollback boundary

The admission unit writes no canonical product state and has no network access;
its verifier may create or update only the local `.state.lock`. Rolling
back this bundle means removing only its copied unit/config/binaries after
capturing evidence. Never delete a state store or independent root as part of an
unreviewed rollback, and never stop existing k3s, AuxPoW, pool/proxy or G4 units.

## Required evidence

Retain the reviewed Git commit, binary SHA-256, independent-root digest, host
survey, exact active-service inventory, approval identity/time, unit verification
output, admission exit status and post-check comparison. Do not put secrets or
regulated record content in that evidence.
