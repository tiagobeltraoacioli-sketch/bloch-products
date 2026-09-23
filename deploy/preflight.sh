#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly CLI_PATH='/usr/local/libexec/bloch-products/bloch-local-state-store'
readonly MIN_TOTAL_MEMORY_KIB_DEFAULT='6291456'
readonly MIN_AVAILABLE_MEMORY_KIB_DEFAULT='524288'
readonly MIN_AVAILABLE_DISK_KIB_DEFAULT='1048576'

fail() {
  printf 'admission refused: %s\n' "$1" >&2
  exit 1
}

info() {
  printf 'admission info: %s\n' "$1"
}

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

require_absolute_path() {
  local path="$1"
  local label="$2"
  [[ "$path" == /* ]] || fail "$label must be an absolute path"
  [[ "$path" != *$'\n'* ]] || fail "$label contains a newline"
  [[ "$path" != */../* && "$path" != */.. && "$path" != *'/./'* ]] || \
    fail "$label contains a traversal component"
}

require_regular_secure_file() {
  local path="$1"
  local label="$2"
  local expected_uid="$3"
  local mode uid links

  [[ ! -L "$path" ]] || fail "$label must not be a symlink"
  [[ -f "$path" ]] || fail "$label must be a regular file"
  mode="$(stat -c '%a' -- "$path")" || fail "cannot stat $label mode"
  uid="$(stat -c '%u' -- "$path")" || fail "cannot stat $label owner"
  links="$(stat -c '%h' -- "$path")" || fail "cannot stat $label link count"
  [[ "$uid" == "$expected_uid" ]] || fail "$label has unexpected owner"
  (( (8#$mode & 0022) == 0 )) || fail "$label is group/other writable"
  (( (8#$mode & 06000) == 0 )) || fail "$label has setuid/setgid bits"
  [[ "$links" == '1' ]] || fail "$label must have exactly one hard link"
}

[[ "$(uname -s)" == 'Linux' ]] || fail 'Linux is required'
script_path="$(readlink -f -- "${BASH_SOURCE[0]}")" || fail 'cannot resolve preflight path'
readonly script_path
[[ "$script_path" == '/usr/local/libexec/bloch-products/preflight.sh' ]] || \
  fail 'preflight is not installed at its fixed path'
require_regular_secure_file "$script_path" 'preflight executable' '0'
[[ $# -eq 2 && "$1" == '--instance' ]] || fail 'usage: preflight.sh --instance NAME'
readonly instance="$2"
[[ "$instance" == 'data' || "$instance" == 'pay' ]] || fail 'instance must be data or pay'

: "${BLOCH_PRODUCT_INSTANCE:?admission refused: BLOCH_PRODUCT_INSTANCE is required}"
: "${BLOCH_ADMISSION_PROFILE:?admission refused: BLOCH_ADMISSION_PROFILE is required}"
: "${BLOCH_STATE_DIR:?admission refused: BLOCH_STATE_DIR is required}"
: "${BLOCH_ROOT_FILE:?admission refused: BLOCH_ROOT_FILE is required}"
: "${BLOCH_COHABITATION_APPROVAL:?admission refused: BLOCH_COHABITATION_APPROVAL is required}"
: "${BLOCH_ENV_FILE:?admission refused: BLOCH_ENV_FILE is required}"
: "${BLOCH_CLI_SHA256:?admission refused: BLOCH_CLI_SHA256 is required}"

[[ "$BLOCH_PRODUCT_INSTANCE" == "$instance" ]] || fail 'instance and environment disagree'
[[ "$BLOCH_ADMISSION_PROFILE" == 'synthetic-pilot' ]] || \
  fail 'only the synthetic-pilot admission profile is authorized'
[[ "$BLOCH_STATE_DIR" == "/var/lib/bloch-products/$instance" ]] || \
  fail 'state directory differs from the admitted per-product path'
[[ "$BLOCH_ROOT_FILE" == "/etc/bloch-products/roots/$instance.root.json" ]] || \
  fail 'independent-root source differs from the systemd credential source'
[[ "$BLOCH_COHABITATION_APPROVAL" == "/etc/bloch-products/approvals/$instance.cohabitation" ]] || \
  fail 'cohabitation approval differs from the admitted per-product path'
[[ "$BLOCH_ENV_FILE" == "/etc/bloch-products/$instance.env" ]] || \
  fail 'environment file differs from the systemd instance path'
require_absolute_path "$BLOCH_STATE_DIR" 'state directory'
require_absolute_path "$BLOCH_ROOT_FILE" 'independent root'
require_absolute_path "$BLOCH_COHABITATION_APPROVAL" 'cohabitation approval'
require_absolute_path "$BLOCH_ENV_FILE" 'environment file'

[[ -x "$CLI_PATH" && ! -L "$CLI_PATH" ]] || fail 'pinned CLI is absent, non-executable or a symlink'
require_regular_secure_file "$CLI_PATH" 'pinned CLI' '0'
require_regular_secure_file "$BLOCH_ENV_FILE" 'environment file' '0'
require_regular_secure_file "$BLOCH_ROOT_FILE" 'independent root' '0'
require_regular_secure_file "$BLOCH_COHABITATION_APPROVAL" 'cohabitation approval' '0'
[[ "$(stat -c '%a' -- "$BLOCH_ENV_FILE")" == '600' ]] || fail 'environment file mode must be 0600'
[[ "$(stat -c '%a' -- "$BLOCH_ROOT_FILE")" == '400' ]] || fail 'independent root mode must be 0400'
[[ "$(stat -c '%a' -- "$BLOCH_COHABITATION_APPROVAL")" == '400' ]] || \
  fail 'cohabitation approval mode must be 0400'
[[ "$BLOCH_CLI_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'CLI SHA-256 is not lowercase hexadecimal'
actual_cli_sha256="$(sha256sum -- "$CLI_PATH" | awk '{ print $1 }')" || fail 'cannot hash pinned CLI'
readonly actual_cli_sha256
[[ "$actual_cli_sha256" == "$BLOCH_CLI_SHA256" ]] || fail 'CLI SHA-256 does not match the reviewed release'

readonly approval_text="APPROVED_INSTANCE=$instance"
approval_bytes="$(wc -c < "$BLOCH_COHABITATION_APPROVAL")" || fail 'cannot read cohabitation approval'
readonly approval_bytes
[[ "$approval_bytes" == "$(( ${#approval_text} + 1 ))" ]] || \
  fail 'cohabitation approval has unexpected content'
grep -Fxq -- "$approval_text" "$BLOCH_COHABITATION_APPROVAL" || \
  fail 'cohabitation approval does not authorize this instance'

[[ ! -L "$BLOCH_STATE_DIR" && -d "$BLOCH_STATE_DIR" ]] || \
  fail 'state directory is absent, not a directory or a symlink'
readonly service_account="bloch-$instance"
service_uid="$(id -u "$service_account")" || fail 'dedicated service account is absent'
readonly service_uid
state_uid="$(stat -c '%u' -- "$BLOCH_STATE_DIR")" || fail 'cannot read state-directory owner'
state_mode="$(stat -c '%a' -- "$BLOCH_STATE_DIR")" || fail 'cannot read state-directory mode'
readonly state_uid state_mode
[[ "$state_uid" == "$service_uid" ]] || fail 'state directory has unexpected owner'
[[ "$state_mode" == '700' ]] || fail 'state directory mode must be 0700'

canonical_state="$(readlink -f -- "$BLOCH_STATE_DIR")" || fail 'cannot resolve state directory'
canonical_root="$(readlink -f -- "$BLOCH_ROOT_FILE")" || fail 'cannot resolve independent root'
readonly canonical_state canonical_root
[[ "$canonical_state" == "$BLOCH_STATE_DIR" ]] || fail 'state path traverses a symlink'
[[ "$canonical_root" == "$BLOCH_ROOT_FILE" ]] || fail 'independent-root path traverses a symlink'
[[ "$canonical_root" != "$canonical_state" && "$canonical_root" != "$canonical_state/"* ]] || \
  fail 'independent root must not be retained inside the state store'

readonly min_total="${BLOCH_MIN_TOTAL_MEMORY_KIB:-$MIN_TOTAL_MEMORY_KIB_DEFAULT}"
readonly min_available="${BLOCH_MIN_AVAILABLE_MEMORY_KIB:-$MIN_AVAILABLE_MEMORY_KIB_DEFAULT}"
readonly min_disk="${BLOCH_MIN_AVAILABLE_DISK_KIB:-$MIN_AVAILABLE_DISK_KIB_DEFAULT}"
is_uint "$min_total" || fail 'invalid total-memory threshold'
is_uint "$min_available" || fail 'invalid available-memory threshold'
is_uint "$min_disk" || fail 'invalid disk threshold'
(( min_total >= MIN_TOTAL_MEMORY_KIB_DEFAULT )) || fail 'total-memory threshold weakens the minimum'
(( min_available >= MIN_AVAILABLE_MEMORY_KIB_DEFAULT )) || fail 'available-memory threshold weakens the minimum'
(( min_disk >= MIN_AVAILABLE_DISK_KIB_DEFAULT )) || fail 'disk threshold weakens the minimum'

total_memory="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)" || fail 'cannot read total memory'
available_memory="$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)" || fail 'cannot read available memory'
readonly total_memory available_memory
is_uint "$total_memory" || fail 'cannot read total memory'
is_uint "$available_memory" || fail 'cannot read available memory'
(( total_memory >= min_total )) || fail 'total memory is below the admitted threshold'
(( available_memory >= min_available )) || fail 'available memory is below the admitted threshold'

available_disk="$(df -Pk -- "$BLOCH_STATE_DIR" | awk 'NR == 2 { print $4 }')" || \
  fail 'cannot read available disk capacity'
readonly available_disk
is_uint "$available_disk" || fail 'cannot read available disk capacity'
(( available_disk >= min_disk )) || fail 'available disk is below the admitted threshold'

if command -v systemctl >/dev/null 2>&1; then
  for protected_service in k3s k3s-agent auxpow bloch-auxpow stratum haproxy nginx g4-forwarder; do
    if systemctl is-active --quiet "$protected_service.service"; then
      info "protected existing service remains active: $protected_service.service"
    fi
  done
fi

info "read-only host preflight passed for $instance"
