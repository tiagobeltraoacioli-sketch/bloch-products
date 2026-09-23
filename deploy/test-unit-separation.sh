#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo "usage: test-unit-separation.sh" >&2
  exit 2
fi

deploy_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verifier=$deploy_directory/verify-unit-separation.sh
source_unit=$deploy_directory/systemd/bloch-products-synthetic-store-check@.service
test_root=$(mktemp -d "${TMPDIR:-/tmp}/bloch-unit-separation.XXXXXX")

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

new_fixture() {
  fixture=$test_root/$1
  mkdir -p "$fixture/systemd"
  cp "$source_unit" "$fixture/systemd/"
  printf '%s\n' "$fixture"
}

expect_rejection() {
  if "$verifier" "$1" >/dev/null 2>&1; then
    echo "unsafe unit fixture was accepted: $1" >&2
    exit 1
  fi
}

"$verifier" "$deploy_directory"

fixture=$(new_fixture dangling-legacy)
ln -s missing.service "$fixture/systemd/bloch-products-admission@.service"
expect_rejection "$fixture"

fixture=$(new_fixture whitespace-install)
printf '\n [Install] \n Alias = bloch-products-production-admission@.service\n' \
  >>"$fixture/systemd/bloch-products-synthetic-store-check@.service"
expect_rejection "$fixture"

fixture=$(new_fixture dependency)
printf '%s\n' '[Unit]' \
  'Requires=bloch-products-synthetic-store-check@data.service' \
  >"$fixture/systemd/bloch-products-production.target"
expect_rejection "$fixture"

fixture=$(new_fixture alias)
ln -s bloch-products-synthetic-store-check@.service \
  "$fixture/systemd/bloch-products-production-admission@.service"
expect_rejection "$fixture"
