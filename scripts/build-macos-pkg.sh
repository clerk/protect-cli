#!/bin/bash
#
# Sign, package, sign, notarize and staple a macOS .pkg installer for
# clerk-protect.
#
# The binary is built before this runs (the release workflow's sign-macos job,
# with `make binary`): on macOS it carries a Swift shim for the Secure Enclave,
# so it cannot be cross-compiled from Linux the way the other platforms are.
#
# Required environment variables:
#   VERSION                     - Version string (e.g., v1.0.0)
#   APPLE_TEAM_ID               - Apple Developer Team ID
#   APP_IDENTITY                - Developer ID Application certificate name
#   INSTALLER_IDENTITY          - Developer ID Installer certificate name
#   APPLE_ID                    - Apple ID for notarization
#   APPLE_APP_SPECIFIC_PASSWORD - App-specific password for notarization
#
# Usage:
#   ./scripts/build-macos-pkg.sh <arch>
#   where <arch> is "amd64" or "arm64"

set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "Usage: $0 <arch>"
    echo "  arch: amd64 or arm64"
    exit 1
fi

# Map Go arch to Apple arch names
case "$ARCH" in
    amd64)
        APPLE_ARCH="x86_64"
        ;;
    arm64)
        APPLE_ARCH="arm64"
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

VERSION="${VERSION:-dev}"
VERSION_NUM="${VERSION#v}"
BINARY_NAME="clerk-protect"
PKG_IDENTIFIER="com.clerk.protect-cli"
INSTALL_LOCATION="/usr/local/bin"

DIST_DIR="dist"
WORK_DIR="${DIST_DIR}/macos-${ARCH}"
BINARY_PATH="${DIST_DIR}/${BINARY_NAME}-${VERSION}-darwin-${ARCH}"
UNSIGNED_PKG="${WORK_DIR}/${BINARY_NAME}-unsigned.pkg"
SIGNED_PKG="${DIST_DIR}/${BINARY_NAME}-${VERSION}-darwin-${ARCH}.pkg"

echo "==> Building macOS .pkg for ${ARCH}"
echo "    Version: ${VERSION}"
echo "    Binary: ${BINARY_PATH}"

# Verify binary exists
if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Error: Binary not found at ${BINARY_PATH}"
    exit 1
fi

# The binary must be the architecture this package claims. Each architecture is
# built on the same runner against a Swift shim of its own, so a mix-up here
# would ship an arm64 binary in the Intel package.
BUILT_ARCH="$(lipo -archs "$BINARY_PATH")"
if [[ "$BUILT_ARCH" != "$APPLE_ARCH" ]]; then
    echo "Error: ${BINARY_PATH} is ${BUILT_ARCH}, not ${APPLE_ARCH}"
    exit 1
fi

# The binary's minimum macOS must be the floor we support. cgo links through
# clang, whose default deployment target is the build machine's own SDK: a
# binary built without the floor reaching the linker ran fine on the runner and
# would refuse to launch on every older Mac. The Makefile exports it from
# SWIFT_TARGET; this is the check that it arrived.
MACOS_FLOOR="${MACOS_FLOOR:-13.0}"
BUILT_MIN="$(otool -l "$BINARY_PATH" | awk '/LC_BUILD_VERSION/ { found = 1 } found && $1 == "minos" { print $2; exit }')"
if [[ "$BUILT_MIN" != "$MACOS_FLOOR" ]]; then
    echo "Error: ${BINARY_PATH} requires macOS ${BUILT_MIN:-unknown}, not ${MACOS_FLOOR}"
    exit 1
fi

# Create work directory
rm -rf "$WORK_DIR"
mkdir -p "${WORK_DIR}/payload${INSTALL_LOCATION}"

# Copy binary to payload
cp "$BINARY_PATH" "${WORK_DIR}/payload${INSTALL_LOCATION}/${BINARY_NAME}"
chmod 755 "${WORK_DIR}/payload${INSTALL_LOCATION}/${BINARY_NAME}"

# Sign the binary. The hardened runtime needs no entitlement for the Secure
# Enclave key: the key is created and used through the Security framework
# without the data-protection keychain, which is what would need one.
echo "==> Signing binary with Developer ID Application certificate"
codesign --force --options runtime \
    --sign "${APP_IDENTITY}" \
    --timestamp \
    "${WORK_DIR}/payload${INSTALL_LOCATION}/${BINARY_NAME}"

# Verify signature
echo "==> Verifying binary signature"
codesign --verify --deep --strict --verbose=2 \
    "${WORK_DIR}/payload${INSTALL_LOCATION}/${BINARY_NAME}"

# A signature that breaks the binary is a release nobody can run. The runner's
# own architecture can execute its own build (and the Intel one under Rosetta,
# when it is installed); where it cannot, the signature check above stands.
echo "==> Running the signed binary"
if "${WORK_DIR}/payload${INSTALL_LOCATION}/${BINARY_NAME}" --version; then
    :
elif [[ "$APPLE_ARCH" != "$(uname -m)" ]]; then
    echo "    (cannot execute ${APPLE_ARCH} on this $(uname -m) runner; signature verified above)"
else
    echo "Error: the signed binary does not run"
    exit 1
fi

# Build unsigned pkg
echo "==> Building unsigned .pkg"
pkgbuild \
    --root "${WORK_DIR}/payload" \
    --identifier "${PKG_IDENTIFIER}" \
    --version "${VERSION_NUM}" \
    --install-location "/" \
    "$UNSIGNED_PKG"

# Sign the pkg
echo "==> Signing .pkg with Developer ID Installer certificate"
productsign \
    --sign "${INSTALLER_IDENTITY}" \
    --timestamp \
    "$UNSIGNED_PKG" \
    "$SIGNED_PKG"

# Verify pkg signature
echo "==> Verifying .pkg signature"
pkgutil --check-signature "$SIGNED_PKG"

# Notarize the pkg
echo "==> Submitting .pkg for notarization"
xcrun notarytool submit "$SIGNED_PKG" \
    --apple-id "${APPLE_ID}" \
    --password "${APPLE_APP_SPECIFIC_PASSWORD}" \
    --team-id "${APPLE_TEAM_ID}" \
    --wait

# Staple the notarization ticket
echo "==> Stapling notarization ticket"
xcrun stapler staple "$SIGNED_PKG"

# Verify stapling
echo "==> Verifying stapled .pkg"
xcrun stapler validate "$SIGNED_PKG"

# Cleanup
rm -rf "$WORK_DIR"

echo "==> Successfully created signed and notarized .pkg: ${SIGNED_PKG}"
