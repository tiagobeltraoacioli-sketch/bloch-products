#!/bin/sh
set -eu

fail() {
  echo "authenticated admission specification refused: $1" >&2
  exit 1
}

if [ "$#" -gt 1 ]; then
  echo "usage: verify-authenticated-admission-spec.sh [deploy-directory]" >&2
  exit 2
fi

if [ "$#" -eq 1 ]; then
  deploy_directory=$1
else
  deploy_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fi

spec_directory=$deploy_directory/systemd-spec
manifest_directory=$spec_directory/manifests
test_root=$(mktemp -d "${TMPDIR:-/tmp}/bloch-systemd-spec.XXXXXX") || \
  fail 'cannot create verifier workspace'
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

[ -d "$spec_directory" ] && [ ! -L "$spec_directory" ] || \
  fail 'specification directory is missing or is a symlink'
[ -d "$manifest_directory" ] && [ ! -L "$manifest_directory" ] || \
  fail 'manifest directory is missing or is a symlink'

symlinks=$(find "$spec_directory" -type l -print 2>/dev/null) || \
  fail 'cannot inspect specification symlinks'
[ -z "$symlinks" ] || fail 'aliases and symlinks are forbidden'

regular_files=$(find "$spec_directory" -type f -print 2>/dev/null | LC_ALL=C sort) || \
  fail 'cannot enumerate specification files'
expected_files=$(printf '%s\n' \
  "$manifest_directory/data.v1.manifest" \
  "$manifest_directory/pay.v1.manifest" \
  "$spec_directory/bloch-products-authenticated-admission-data.service.spec" \
  "$spec_directory/bloch-products-authenticated-admission-pay.service.spec" | LC_ALL=C sort)
[ "$regular_files" = "$expected_files" ] || \
  fail 'specification file set is not exact'

exactly_once() {
  file=$1
  expected=$2
  count=$(awk -v expected="$expected" '$0 == expected { count++ } END { print count + 0 }' "$file") || \
    fail 'cannot inspect required directive'
  [ "$count" -eq 1 ] || fail "required directive is absent or duplicated: $expected"
}

field_exactly_once() {
  file=$1
  field=$2
  count=$(awk -v prefix="$field=" 'index($0, prefix) == 1 { count++ } END { print count + 0 }' "$file") || \
    fail 'cannot inspect directive cardinality'
  [ "$count" -eq 1 ] || fail "field is absent or duplicated: $field"
}

write_expected_credentials() {
  instance=$1
  trust=/etc/bloch-products/trust/$instance
  fetch=/run/bloch-products-fetch/$instance
  printf '%s\n' \
    "remote-observation:$fetch/remote-observation" \
    "request-nonce:$fetch/request-nonce" \
    "fetch-invocation:$fetch/fetch-invocation" \
    "remote-policy:$trust/remote-policy" \
    "remote-policy-pin:$trust/remote-policy-pin" \
    "trusted-time-token:$fetch/trusted-time-token" \
    "trusted-time-request-nonce:$fetch/trusted-time-request-nonce" \
    "trusted-time-policy:$trust/trusted-time-policy" \
    "trusted-time-policy-pin:$trust/trusted-time-policy-pin" \
    "checkpoint-artifact:$fetch/checkpoint-artifact" \
    "checkpoint-policy:$fetch/checkpoint-policy" \
    "semantic-manifest:$fetch/semantic-manifest"
  if [ "$instance" = data ]; then
    printf '%s\n' "lifecycle-policy:$trust/lifecycle-policy"
  fi
  printf '%s\n' "expected-state-identity:$trust/expected-state-identity"
}

verify_instance() {
  instance=$1
  peer=$2
  manifest=$manifest_directory/$instance.v1.manifest
  unit_name=bloch-products-authenticated-admission-$instance.service.spec
  unit=$spec_directory/$unit_name
  user=bloch-$instance
  fetch_user=bloch-$instance-fetch
  state_root=/var/lib/bloch-products/$instance
  coord=/run/bloch-products/$instance/coord
  trust=/etc/bloch-products/trust/$instance
  fetch=/run/bloch-products-fetch/$instance

  [ -f "$manifest" ] && [ ! -L "$manifest" ] || fail "$instance manifest is unsafe"
  [ -f "$unit" ] && [ ! -L "$unit" ] || fail "$instance unit specification is unsafe"
  if LC_ALL=C grep -q "$(printf '\r')" "$manifest" "$unit"; then
    fail 'carriage returns are not canonical'
  fi

  if ! awk -F= '
    NF < 2 { exit 1 }
    $1 !~ /^(schema|artifact|instance|service-spec|user|group|fetch-user|peer-user|uid-requirement|state-path|cursor-path|trusted-time-boundary-path|coordination-path|trust-path|fetch-path|credential|network|sandbox|resources)$/ { exit 1 }
  ' "$manifest"; then
    fail "$instance manifest contains an unknown or malformed field"
  fi

  for field in schema artifact instance service-spec user group fetch-user \
    peer-user uid-requirement state-path cursor-path \
    trusted-time-boundary-path coordination-path trust-path fetch-path network \
    sandbox resources; do
    field_exactly_once "$manifest" "$field"
  done

  exactly_once "$manifest" 'schema=bloch.products.authenticated-admission-systemd-spec.v1'
  exactly_once "$manifest" 'artifact=specification-check-only'
  exactly_once "$manifest" "instance=$instance"
  exactly_once "$manifest" "service-spec=$unit_name"
  exactly_once "$manifest" "user=$user"
  exactly_once "$manifest" "group=$user"
  exactly_once "$manifest" "fetch-user=$fetch_user"
  exactly_once "$manifest" "peer-user=bloch-$peer"
  exactly_once "$manifest" 'uid-requirement=dedicated-locked-numeric-host-record'
  exactly_once "$manifest" "state-path=$state_root/state"
  exactly_once "$manifest" "cursor-path=$state_root/cursor"
  exactly_once "$manifest" "trusted-time-boundary-path=$state_root/trusted-time-boundary"
  exactly_once "$manifest" "coordination-path=$coord"
  exactly_once "$manifest" "trust-path=$trust"
  exactly_once "$manifest" "fetch-path=$fetch"
  exactly_once "$manifest" 'network=offline-private'
  exactly_once "$manifest" 'sandbox=baseline-v1'
  exactly_once "$manifest" 'resources=CPUQuota=25%;MemoryHigh=256M;MemoryMax=512M;TasksMax=32;LimitNOFILE=128;LimitFSIZE=32M;IOWeight=10'

  expected_credentials=$test_root/$instance.credentials.expected
  manifest_credentials=$test_root/$instance.credentials.manifest
  unit_credentials=$test_root/$instance.credentials.unit
  write_expected_credentials "$instance" >"$expected_credentials"
  sed -n 's/^credential=//p' "$manifest" >"$manifest_credentials"
  sed -n 's/^LoadCredential=//p' "$unit" >"$unit_credentials"
  cmp -s "$expected_credentials" "$manifest_credentials" || \
    fail "$instance manifest credential set/order/path is not exact"
  cmp -s "$expected_credentials" "$unit_credentials" || \
    fail "$instance unit credential set/order/path is not exact"

  if ! awk -F= '
    /^[[:space:]]*($|#)/ { next }
    /^\[(Unit|Service)\]$/ { next }
    $1 !~ /^(Description|X-Bloch-Artifact|Type|User|Group|UMask|LoadCredential|ExecStart|NoNewPrivileges|PrivateDevices|PrivateNetwork|PrivateTmp|ProtectClock|ProtectControlGroups|ProtectHome|ProtectHostname|ProtectKernelLogs|ProtectKernelModules|ProtectKernelTunables|ProtectProc|ProtectSystem|ReadWritePaths|InaccessiblePaths|RestrictAddressFamilies|IPAddressDeny|RestrictNamespaces|RestrictRealtime|RestrictSUIDSGID|LockPersonality|MemoryDenyWriteExecute|CapabilityBoundingSet|AmbientCapabilities|DevicePolicy|SystemCallArchitectures|CPUQuota|MemoryHigh|MemoryMax|TasksMax|LimitNOFILE|LimitFSIZE|IOWeight|OOMPolicy)$/ { exit 1 }
  ' "$unit"; then
    fail "$instance unit contains an unreviewed directive or section"
  fi

  unit_sections=$(awk '/^\[(Unit|Service)\]$/ { print }' "$unit")
  [ "$unit_sections" = "[Unit]
[Service]" ] || fail "$instance unit sections are absent, duplicated or reordered"
  for field in Description X-Bloch-Artifact Type User Group UMask ExecStart \
    NoNewPrivileges PrivateDevices PrivateNetwork PrivateTmp ProtectClock \
    ProtectControlGroups ProtectHome ProtectHostname ProtectKernelLogs \
    ProtectKernelModules ProtectKernelTunables ProtectProc ProtectSystem \
    ReadWritePaths InaccessiblePaths RestrictAddressFamilies \
    IPAddressDeny RestrictNamespaces RestrictRealtime RestrictSUIDSGID \
    LockPersonality MemoryDenyWriteExecute CapabilityBoundingSet \
    AmbientCapabilities DevicePolicy SystemCallArchitectures CPUQuota \
    MemoryHigh MemoryMax TasksMax LimitNOFILE LimitFSIZE IOWeight OOMPolicy; do
    field_exactly_once "$unit" "$field"
  done

  if [ "$instance" = data ]; then
    exactly_once "$unit" 'Description=Bloch Data authenticated admission specification (never deploy)'
  else
    exactly_once "$unit" 'Description=Bloch Pay authenticated admission specification (never deploy)'
  fi
  exactly_once "$unit" 'X-Bloch-Artifact=specification-check-only'
  exactly_once "$unit" 'Type=oneshot'
  exactly_once "$unit" "User=$user"
  exactly_once "$unit" "Group=$user"
  exactly_once "$unit" 'UMask=0077'
  exactly_once "$unit" 'ExecStart=/usr/bin/false'
  exactly_once "$unit" 'PrivateNetwork=yes'
  exactly_once "$unit" 'RestrictAddressFamilies=AF_UNIX'
  exactly_once "$unit" 'IPAddressDeny=any'
  exactly_once "$unit" "ReadWritePaths=$state_root/state $state_root/cursor $state_root/trusted-time-boundary $coord"
  exactly_once "$unit" "InaccessiblePaths=$trust $fetch /var/lib/bloch-products/$peer /run/bloch-products/$peer /etc/bloch-products/trust/$peer /run/bloch-products-fetch/$peer"
  for directive in \
    NoNewPrivileges PrivateDevices PrivateTmp ProtectClock ProtectControlGroups \
    ProtectHome ProtectHostname ProtectKernelLogs ProtectKernelModules \
    ProtectKernelTunables RestrictNamespaces RestrictRealtime RestrictSUIDSGID \
    LockPersonality MemoryDenyWriteExecute; do
    exactly_once "$unit" "$directive=yes"
  done
  exactly_once "$unit" 'ProtectProc=invisible'
  exactly_once "$unit" 'ProtectSystem=strict'
  exactly_once "$unit" 'CapabilityBoundingSet='
  exactly_once "$unit" 'AmbientCapabilities='
  exactly_once "$unit" 'DevicePolicy=closed'
  exactly_once "$unit" 'SystemCallArchitectures=native'
  exactly_once "$unit" 'CPUQuota=25%'
  exactly_once "$unit" 'MemoryHigh=256M'
  exactly_once "$unit" 'MemoryMax=512M'
  exactly_once "$unit" 'TasksMax=32'
  exactly_once "$unit" 'LimitNOFILE=128'
  exactly_once "$unit" 'LimitFSIZE=32M'
  exactly_once "$unit" 'IOWeight=10'
  exactly_once "$unit" 'OOMPolicy=stop'

  if grep -Eq '^[[:space:]]*\[Install\][[:space:]]*$|^[[:space:]]*(Alias|WantedBy|RequiredBy|Requires|Wants|BindsTo|PartOf|Upholds)[[:space:]]*=' "$unit"; then
    fail "$instance specification is installable, aliased or dependency-bearing"
  fi
  if grep -Eq 'AF_INET|AF_INET6|PrivateNetwork[[:space:]]*=[[:space:]]*(no|false|0)|IPAddressAllow' "$unit"; then
    fail "$instance offline specification enables network access"
  fi
  if grep -Fq 'synthetic-store-check' "$unit"; then
    fail "$instance specification depends on the synthetic check"
  fi
}

verify_instance data pay
verify_instance pay data
