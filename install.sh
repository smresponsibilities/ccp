#!/usr/bin/env sh
set -e

REPO="${CCP_REPO:-smresponsibilities/ccp}"

# Detect Operating System (macOS, Linux, WSL)
OS="$(uname -s)"
case "$OS" in
  Linux)
    OS="linux"
    ;;
  Darwin)
    OS="darwin"
    ;;
  *)
    echo "❌ Unsupported operating system: $OS"
    exit 1
    ;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  *)
    echo "❌ Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

ASSET_NAME="ccp-${OS}-${ARCH}.tar.gz"

# CCP_DOWNLOAD_BASE lets you install from a mirror (or a local server when testing).
if [ -n "$CCP_DOWNLOAD_BASE" ]; then
  DOWNLOAD_URL="${CCP_DOWNLOAD_BASE%/}/${ASSET_NAME}"
elif [ -n "$CCP_VERSION" ]; then
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${CCP_VERSION}/${ASSET_NAME}"
else
  DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
fi

# Determine install location (default: ~/.local/bin)
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

echo "==> Installing ccp (${OS}/${ARCH})..."
echo "==> Downloading from: $DOWNLOAD_URL"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'ccp')"
trap 'rm -rf "$TMP_DIR"' EXIT

if ! curl -fSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME"; then
  echo "❌ Failed to download $ASSET_NAME."
  echo "Please check if a release exists at https://github.com/${REPO}/releases"
  exit 1
fi

# Verify the download against the SHA-256 published next to it. This catches corrupted or
# truncated downloads and a tampered CDN/mirror; it cannot protect against a compromised
# GitHub account, since the checksum comes from the same release.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    return 1
  fi
}

if [ "$CCP_SKIP_VERIFY" = "1" ]; then
  echo "⚠️  Skipping checksum verification (CCP_SKIP_VERIFY=1)."
else
  if ! curl -fsSL "${DOWNLOAD_URL}.sha256" -o "$TMP_DIR/$ASSET_NAME.sha256"; then
    echo "❌ Could not download the checksum file (${DOWNLOAD_URL}.sha256)."
    echo "   Refusing to install an unverified binary. Set CCP_SKIP_VERIFY=1 to override."
    exit 1
  fi
  EXPECTED="$(cut -d ' ' -f 1 "$TMP_DIR/$ASSET_NAME.sha256" | tr -d '[:space:]' | tr 'A-F' 'a-f')"
  if ! ACTUAL="$(sha256_of "$TMP_DIR/$ASSET_NAME")"; then
    echo "❌ Neither sha256sum nor shasum is available to verify the download."
    echo "   Install one, or set CCP_SKIP_VERIFY=1 to override."
    exit 1
  fi
  if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "❌ Checksum mismatch for $ASSET_NAME. Not installing."
    echo "   expected: $EXPECTED"
    echo "   actual:   $ACTUAL"
    exit 1
  fi
  echo "==> Checksum verified."
fi

tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR" ccp

mkdir -p "$INSTALL_DIR"
mv "$TMP_DIR/ccp" "$INSTALL_DIR/ccp"
chmod +x "$INSTALL_DIR/ccp"

echo "✅ ccp installed to $INSTALL_DIR/ccp"

# Check if INSTALL_DIR is in PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo ""
    echo "⚠️  $INSTALL_DIR is not in your PATH."
    echo "Add it by running:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo "Or append it to your ~/.bashrc or ~/.zshrc."
    ;;
esac

echo ""
echo "Next steps:"
echo "  1. ccp set        # save your campus username and password"
echo "  2. ccp            # log in once (on campus Wi-Fi) and approve your portal"
echo "  3. ccp autostart enable --now   # keep it logged in automatically"
