#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd);
TARGET_DIR="$1";
MBEDTLS_VERSION="4.0.0";

download() {
  url=$1
  out=$2

  if command -v curl >/dev/null 2>&1; then
    curl -L -o "$out" "$url";
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$out" "$url";
  else
    printf '%s\n' "Neither curl nor wget is installed" >&2;
    exit 1;
  fi;
}

set -x

# download module sources
download "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2" \
  "${SCRIPT_DIR}/mbedtls.tar.bz2";

# extract archive files
tar -vxjf "${SCRIPT_DIR}/mbedtls.tar.bz2" -C "${SCRIPT_DIR}";

# remove archive files
rm "${SCRIPT_DIR}/mbedtls.tar.bz2";

# rename extracted folder
mv "${SCRIPT_DIR}/mbedtls-${MBEDTLS_VERSION}" "${TARGET_DIR}";

# apply patches
cd "${TARGET_DIR}" || exit 1;
for f in "${SCRIPT_DIR}"/patches/mbedtls4/*.patch; do patch -p1 < "$f"; done
