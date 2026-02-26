#!/bin/bash
set -euo pipefail

# =============================================================================
# PPA Upload Script for MCP Client
# =============================================================================
# Builds source packages for multiple Ubuntu releases and uploads to the PPA.
#
# Usage:
#   ./scripts/ppa-upload.sh <version> [--upload] [--gpg-key KEY_ID]
#
# Examples:
#   ./scripts/ppa-upload.sh 0.2.0                    # Build only (dry run)
#   ./scripts/ppa-upload.sh 0.2.0 --upload            # Build and upload to PPA
#   ./scripts/ppa-upload.sh 0.2.0 --upload --gpg-key ABCD1234
#
# Requirements (Ubuntu/Debian):
#   sudo apt install devscripts debhelper dput gpg golang-go
#
# Requirements (Docker - for macOS/other):
#   docker run --rm -v $(pwd):/src -v ~/.gnupg:/root/.gnupg ubuntu:24.04 \
#     bash -c "apt update && apt install -y devscripts debhelper dput golang-go gpg && /src/scripts/ppa-upload.sh 0.2.0 --upload"
# =============================================================================

PACKAGE="smcp"
PPA="ppa:mcphub/smcp"
RELEASES=("noble" "jammy")
MAINTAINER="Dani <cr0hn@cr0hn.com>"

# --- Parse arguments ---
VERSION=""
DO_UPLOAD=false
GPG_KEY=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --upload) DO_UPLOAD=true; shift ;;
        --gpg-key) GPG_KEY="$2"; shift 2 ;;
        -*) echo "Unknown option: $1"; exit 1 ;;
        *) VERSION="$1"; shift ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version> [--upload] [--gpg-key KEY_ID]"
    echo ""
    echo "  version    Upstream version (e.g., 0.2.0)"
    echo "  --upload   Upload to PPA after building"
    echo "  --gpg-key  GPG key ID for signing"
    exit 1
fi

# --- Setup ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$(mktemp -d)"
ORIG_TARBALL="${PACKAGE}_${VERSION}.orig.tar.gz"

# --- Check platform and tools ---
if [[ "$(uname)" == "Darwin" ]]; then
    # Check if debuild is available (e.g. via Docker)
    if ! command -v debuild &>/dev/null; then
        echo ""
        echo "WARNING: You are on macOS. 'debuild' and 'dput' are not available natively."
        echo ""
        echo "This script will create the orig tarball, then you need to run the"
        echo "Debian packaging step inside Docker or on an Ubuntu machine."
        echo ""
        echo "Quick Docker option (run from mcp-client/):"
        echo "  docker run --rm -it \\"
        echo "    -v \$(pwd):/src \\"
        echo "    -v ~/.gnupg:/root/.gnupg \\"
        echo "    -w /src \\"
        echo "    ubuntu:24.04 bash -c \\"
        echo "    'apt-get update && apt-get install -y devscripts debhelper dput gpg golang-go rsync && ./scripts/ppa-upload.sh $VERSION ${DO_UPLOAD:+--upload} ${GPG_KEY:+--gpg-key $GPG_KEY}'"
        echo ""
        MACOS_NO_DEBUILD=true
    fi
fi

echo "=== SMCP PPA Builder ==="
echo "Package:  $PACKAGE"
echo "Version:  $VERSION"
echo "PPA:      $PPA"
echo "Releases: ${RELEASES[*]}"
echo "Upload:   $DO_UPLOAD"
echo "Build:    $BUILD_DIR"
echo ""

# --- Step 1: Vendor dependencies ---
echo ">>> Vendoring Go dependencies..."
cd "$PROJECT_DIR"
go mod vendor
echo "    Done. vendor/ contains $(find vendor -name '*.go' | wc -l | tr -d ' ') Go files."

# --- Step 2: Create orig tarball ---
echo ">>> Creating upstream tarball: $ORIG_TARBALL"
STAGING_DIR="$(mktemp -d)"
STAGING_SRC="$STAGING_DIR/${PACKAGE}-${VERSION}"
mkdir -p "$STAGING_SRC"

# Copy source files (excluding VCS metadata and build artifacts)
rsync -a \
    --exclude='.git' \
    --exclude='debian' \
    --exclude='.DS_Store' \
    --exclude='bin/' \
    --exclude='coverage.out' \
    --exclude='.gopath' \
    --exclude='.gocache' \
    "$PROJECT_DIR/" "$STAGING_SRC/"

tar czf "$BUILD_DIR/$ORIG_TARBALL" -C "$STAGING_DIR" "${PACKAGE}-${VERSION}"
rm -rf "$STAGING_DIR"
echo "    Size: $(du -h "$BUILD_DIR/$ORIG_TARBALL" | cut -f1)"

# --- Step 3: Build source package for each release ---
if [[ "${MACOS_NO_DEBUILD:-}" == "true" ]]; then
    echo ""
    echo "=== Tarball Created ==="
    echo "Orig tarball: $BUILD_DIR/$ORIG_TARBALL"
    echo ""
    echo "To continue, run inside Docker or on Ubuntu (see instructions above)."
    exit 0
fi

GPG_ARGS=""
if [[ -n "$GPG_KEY" ]]; then
    GPG_ARGS="-k$GPG_KEY"
fi

for release in "${RELEASES[@]}"; do
    echo ""
    echo ">>> Building source package for $release..."

    # Create working directory
    WORK_DIR="$BUILD_DIR/${PACKAGE}-${VERSION}-${release}"
    mkdir -p "$WORK_DIR"

    # Extract orig tarball
    cd "$BUILD_DIR"
    tar xzf "$ORIG_TARBALL"
    mv "${PACKAGE}-${VERSION}" "$WORK_DIR/src"

    # Copy debian directory
    cp -r "$PROJECT_DIR/debian" "$WORK_DIR/src/debian"

    # Generate release-specific changelog
    RELEASE_VERSION="${VERSION}-1~${release}1"
    DATE=$(date -R)
    cat > "$WORK_DIR/src/debian/changelog" << CHANGELOG
${PACKAGE} (${RELEASE_VERSION}) ${release}; urgency=medium

  * Release v${VERSION} for ${release}.
  * CLI launcher for certified MCP servers.
  * SHA-256 digest validation, sandboxing, and audit logging.

 -- ${MAINTAINER}  ${DATE}
CHANGELOG

    # Copy orig tarball to expected location
    cp "$BUILD_DIR/$ORIG_TARBALL" "$WORK_DIR/${ORIG_TARBALL}"

    # Build source package
    cd "$WORK_DIR/src"
    debuild -S -sa -d $GPG_ARGS

    # Move results
    mkdir -p "$BUILD_DIR/output"
    mv "$WORK_DIR"/${PACKAGE}_${RELEASE_VERSION}* "$BUILD_DIR/output/" 2>/dev/null || true
    cp "$BUILD_DIR/$ORIG_TARBALL" "$BUILD_DIR/output/" 2>/dev/null || true

    echo "    Built: ${PACKAGE}_${RELEASE_VERSION}_source.changes"

    # Upload if requested
    if $DO_UPLOAD; then
        echo "    Uploading to $PPA..."
        dput "$PPA" "$BUILD_DIR/output/${PACKAGE}_${RELEASE_VERSION}_source.changes"
        echo "    Uploaded!"
    fi

    # Cleanup working dir
    rm -rf "$WORK_DIR"
done

echo ""
echo "=== Build Complete ==="
echo "Output files in: $BUILD_DIR/output/"
ls -la "$BUILD_DIR/output/" 2>/dev/null || true

if ! $DO_UPLOAD; then
    echo ""
    echo "Dry run complete. To upload, re-run with --upload flag."
    echo "Or upload manually:"
    for release in "${RELEASES[@]}"; do
        RELEASE_VERSION="${VERSION}-1~${release}1"
        echo "  dput $PPA $BUILD_DIR/output/${PACKAGE}_${RELEASE_VERSION}_source.changes"
    done
fi
