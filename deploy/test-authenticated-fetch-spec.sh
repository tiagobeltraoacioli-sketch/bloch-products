#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo 'usage: test-authenticated-fetch-spec.sh' >&2
  exit 2
fi

deploy_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verifier=$deploy_directory/verify-authenticated-fetch-spec.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/bloch-fetch-spec-test.XXXXXX")
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

new_fixture() {
  name=$1
  fixture=$test_root/$name
  mkdir -p "$fixture"
  cp -R "$deploy_directory/systemd-fetch-spec" "$fixture/"
  printf '%s\n' "$fixture"
}

expect_rejection() {
  if "$verifier" "$1" >/dev/null 2>&1; then
    echo "unsafe authenticated-fetch fixture was accepted: $1" >&2
    exit 1
  fi
}

"$verifier" "$deploy_directory"

fixture=$(new_fixture alias)
ln -s bloch-products-authenticated-fetch-data.service.spec \
  "$fixture/systemd-fetch-spec/data-alias.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture missing-policy-pin)
sed '/^LoadCredential=transport-policy-pin:/d' \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-data.service.spec" \
  >"$fixture/changed"
mv "$fixture/changed" \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-data.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture raw-private-key)
printf '%s\n' 'LoadCredential=mtls-private-key:/tmp/client.key' >> \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-pay.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture state-write)
sed 's#ReadWritePaths=/run/bloch-products-fetch/data#ReadWritePaths=/var/lib/bloch-products/data/state#' \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-data.service.spec" \
  >"$fixture/changed"
mv "$fixture/changed" \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-data.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture offline-fetch)
sed 's/^PrivateNetwork=no$/PrivateNetwork=yes/' \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-pay.service.spec" \
  >"$fixture/changed"
mv "$fixture/changed" \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-pay.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture cross-uid)
sed 's/^User=bloch-data-fetch$/User=bloch-data/' \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-data.service.spec" \
  >"$fixture/changed"
mv "$fixture/changed" \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-data.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture installable)
printf '%s\n' '[Install]' 'WantedBy=multi-user.target' >> \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-pay.service.spec"
expect_rejection "$fixture"

fixture=$(new_fixture dependency)
printf '%s\n' 'Requires=bloch-products-synthetic-store-check@data.service' >> \
  "$fixture/systemd-fetch-spec/bloch-products-authenticated-fetch-data.service.spec"
expect_rejection "$fixture"
