#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'credential admission refused: %s\n' "$1" >&2
  exit 1
}

[[ "$(uname -s)" == 'Linux' ]] || fail 'Linux is required'
script_path="$(readlink -f -- "${BASH_SOURCE[0]}")" || fail 'cannot resolve credential-preflight path'
readonly script_path
[[ "$script_path" == '/usr/local/libexec/bloch-products/credential-preflight.sh' ]] || \
  fail 'credential preflight is not installed at its fixed path'
[[ -f "$script_path" && ! -L "${BASH_SOURCE[0]}" ]] || \
  fail 'credential preflight must be a regular non-symlink file'
script_mode="$(stat -c '%a' -- "$script_path")" || fail 'cannot inspect credential-preflight mode'
script_uid="$(stat -c '%u' -- "$script_path")" || fail 'cannot inspect credential-preflight owner'
script_links="$(stat -c '%h' -- "$script_path")" || fail 'cannot inspect credential-preflight links'
readonly script_mode script_uid script_links
[[ "$script_uid" == '0' ]] || fail 'credential preflight must be root-owned'
[[ "$script_links" == '1' ]] || fail 'credential preflight must have one hard link'
(( (8#$script_mode & 06022) == 0 )) || \
  fail 'credential preflight is writable or has setuid/setgid bits'
[[ $# -eq 2 && "$1" == '--root' ]] || \
  fail 'usage: credential-preflight.sh --root CREDENTIAL_PATH'
readonly credential="$2"
: "${CREDENTIALS_DIRECTORY:?credential admission refused: systemd credential directory is absent}"
[[ "$credential" == "$CREDENTIALS_DIRECTORY/state-root" ]] || \
  fail 'credential path differs from the systemd-provided root'
[[ ! -L "$credential" && -f "$credential" ]] || \
  fail 'staged root must be a regular non-symlink file'

mode="$(stat -c '%a' -- "$credential")" || fail 'cannot inspect staged-root mode'
uid="$(stat -c '%u' -- "$credential")" || fail 'cannot inspect staged-root owner'
gid="$(stat -c '%g' -- "$credential")" || fail 'cannot inspect staged-root group'
links="$(stat -c '%h' -- "$credential")" || fail 'cannot inspect staged-root link count'
size="$(stat -c '%s' -- "$credential")" || fail 'cannot inspect staged-root size'
readonly mode uid gid links size
effective_uid="$(id -u)" || fail 'cannot determine verifier uid'
readonly effective_uid
[[ "$effective_uid" != '0' ]] || fail 'credential preflight must run as an unprivileged user'

[[ "$mode" == '440' ]] || fail 'staged root mode is not the systemd credential mode 0440'
[[ "$uid" == '0' ]] || fail 'staged root is not root-owned'
[[ "$gid" == '0' ]] || fail 'staged root is not root-group-owned'
[[ "$links" == '1' ]] || fail 'staged root must have exactly one hard link'
[[ "$size" =~ ^[0-9]+$ ]] || fail 'staged-root size is invalid'
(( size > 0 && size <= 1024 )) || fail 'staged-root size is outside the CLI bound'

printf 'credential admission passed: uid=%s gid=%s mode=%s links=%s bytes=%s\n' \
  "$uid" "$gid" "$mode" "$links" "$size"
