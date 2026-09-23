#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo 'usage: test-authenticated-admission-spec.sh' >&2
  exit 2
fi

deploy_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verifier=$deploy_directory/verify-authenticated-admission-spec.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/bloch-systemd-spec-test.XXXXXX")
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

new_fixture() {
  name=$1
  fixture=$test_root/$name
  mkdir -p "$fixture"
  cp -R "$deploy_directory/systemd-spec" "$fixture/"
  printf '%s\n' "$fixture"
}

expect_rejection() {
  if "$verifier" "$1" >/dev/null 2>&1; then
    echo "unsafe authenticated-admission fixture was accepted: $1" >&2
    exit 1
  fi
}

"$verifier" "$deploy_directory"

fixture=$(new_fixture alias)
ln -s bloch-products-authenticated-admission-data.service.spec \
  "$fixture/systemd-spec/data-alias.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture missing-credential)
sed '/^LoadCredential=request-nonce:/d' \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-data.service.spec" \
  >"$fixture/data.changed"
mv "$fixture/data.changed" \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-data.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture extra-credential)
printf '%s\n' 'LoadCredential=unreviewed:/tmp/unreviewed' >> \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-pay.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture duplicate-credential)
printf '%s\n' 'LoadCredential=request-nonce:/run/bloch-products-fetch/data/request-nonce' >> \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-data.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture network-enabled)
sed 's/^PrivateNetwork=yes$/PrivateNetwork=no/' \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-pay.service.spec" \
  >"$fixture/pay.changed"
mv "$fixture/pay.changed" \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-pay.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture contradictory-network-duplicate)
printf '%s\n' 'PrivateNetwork=no' >> \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-data.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture synthetic-dependency)
printf '%s\n' 'Requires=bloch-products-synthetic-store-check@data.service' >> \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-data.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture unsafe-path)
sed 's#/var/lib/bloch-products/pay/state#/tmp/pay-state#' \
  "$fixture/systemd-spec/manifests/pay.v1.manifest" >"$fixture/pay.changed"
mv "$fixture/pay.changed" "$fixture/systemd-spec/manifests/pay.v1.manifest"
expect_rejection "$fixture"

fixture=$(new_fixture cross-uid)
sed 's/^User=bloch-data$/User=bloch-pay/' \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-data.service.spec" \
  >"$fixture/data.changed"
mv "$fixture/data.changed" \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-data.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture installable)
printf '%s\n' '[Install]' 'WantedBy=multi-user.target' >> \
  "$fixture/systemd-spec/bloch-products-authenticated-admission-pay.service.spec"
expect_rejection "$fixture"
