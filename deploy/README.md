# Bloch products deployment bundle

This synthetic-only bundle checks an existing local Bloch Data or Bloch Pay
state store on a small Unix node. It is deliberately not authenticated product
admission or a daemon deployment and does not
install, stop, restart or reconfigure k3s, AuxPoW, pool, proxy or G4 services.

The systemd template runs three storage checks:

1. `preflight.sh` validates the host, file ownership and modes, independent
   root placement, capacity and an explicit cohabitation approval marker.
2. `credential-preflight.sh` confirms that systemd exposed the staged root with
   the owner, mode, link count and bound required by the unprivileged verifier.
3. `bloch-local-state-store verify` validates the store against the staged
   canonical root. It may create or update the local store lock file while
   taking the bounded lock, but does not rewrite canonical product state.

All three checks must succeed. Separate `bloch-data` and `bloch-pay` accounts own
their respective stores. No canonical product state is written by the unit. See
[`docs/deployment/AUXPOW-8GB-ADMISSION.md`](../docs/deployment/AUXPOW-8GB-ADMISSION.md)
for the reviewed installation plan.

Files:

- `systemd/bloch-products-synthetic-store-check@.service`: explicitly named
  synthetic storage-check oneshot; it is not a production admission unit and
  has no install relationship to any production target.
- `systemd/bloch-products.tmpfiles.conf`: optional directory declarations;
  review before using and never apply blindly on an occupied host. It includes
  isolated `state`, `cursor` and boot-scoped `coord` paths for the future
  authenticated flow; creating those paths does not activate that flow. An
  empty recreated state/cursor directory after prior use is an incident and
  never authorization to bootstrap generation zero.
- `config/data.env.example` and `config/pay.env.example`: non-secret examples.
- `preflight.sh`: read-only host and file admission checks.
- `credential-preflight.sh`: checks the staged credential metadata as the
  unprivileged product user without printing its contents.
- `verify-unit-separation.sh`: static negative check that the synthetic unit is
  not legacy-named, installable, aliased or referenced by another bundled
  systemd unit.
- `test-unit-separation.sh`: adversarial fixtures for dangling legacy names,
  whitespace-obscured install directives, target dependencies and aliases.

This synthetic-pilot bundle does not yet authenticate the staged root through
`bloch-local-state-checkpoint` or a remote monotonic cursor. It provides no
encryption, key management, backup, replication, high availability, custody,
settlement, regulatory approval or production admission.
