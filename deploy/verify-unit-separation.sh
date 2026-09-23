#!/bin/sh
set -eu

if [ "$#" -gt 1 ]; then
  echo "usage: verify-unit-separation.sh [deploy-directory]" >&2
  exit 2
fi

if [ "$#" -eq 1 ]; then
  deploy_directory=$1
else
  deploy_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fi

systemd_directory=$deploy_directory/systemd
synthetic_unit=$systemd_directory/bloch-products-synthetic-store-check@.service
legacy_unit=$systemd_directory/bloch-products-admission@.service

if [ -e "$legacy_unit" ] || [ -L "$legacy_unit" ]; then
  echo "legacy admission-named synthetic unit is forbidden" >&2
  exit 1
fi
if [ ! -f "$synthetic_unit" ] || [ -L "$synthetic_unit" ]; then
  echo "synthetic store-check unit is missing or unsafe" >&2
  exit 1
fi
if ! grep -Eq '^[[:space:]]*Description[[:space:]]*=[[:space:]]*Bloch products synthetic storage-only check for %i \(never production admission\)[[:space:]]*$' "$synthetic_unit"; then
  echo "synthetic unit description lost its explicit classification" >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*\[Install\][[:space:]]*$|^[[:space:]]*(WantedBy|RequiredBy|Alias)[[:space:]]*=' "$synthetic_unit"; then
  echo "synthetic unit must not be installable or aliased" >&2
  exit 1
fi
set +e
symlinks=$(find "$systemd_directory" -type l -print 2>/dev/null)
find_status=$?
set -e
if [ "$find_status" -ne 0 ]; then
  echo "failed to inspect systemd bundle" >&2
  exit 1
fi
if [ -n "$symlinks" ]; then
  echo "systemd bundle must not contain symlinks or aliases" >&2
  exit 1
fi

set +e
references=$(grep -R -F -l 'bloch-products-synthetic-store-check@' "$systemd_directory" 2>/dev/null)
grep_status=$?
set -e
if [ "$grep_status" -gt 1 ]; then
  echo "failed to inspect systemd references" >&2
  exit 1
fi

old_ifs=$IFS
IFS='
'
for reference in $references; do
  if [ "$reference" != "$synthetic_unit" ]; then
    echo "another systemd unit depends on the synthetic store check" >&2
    exit 1
  fi
done
IFS=$old_ifs
