#!/usr/bin/env bash
set -euo pipefail

REPO="bloccooo/envisible"
BIN="envi"
INSTALL_DIR="/usr/local/bin"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    TARGET="linux-x64"
    ;;
  Darwin)
    case "$ARCH" in
      arm64) TARGET="darwin-arm64" ;;
      x86_64) TARGET="darwin-x64" ;;
      *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

# Resolve latest release tag via redirect (avoids api.github.com rate limits)
echo "Fetching latest release..."
TAG="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's#.*/tag/##')"

if [ -z "$TAG" ]; then
  echo "Could not determine latest release tag."
  exit 1
fi

URL="https://github.com/$REPO/releases/download/$TAG/$BIN-$TARGET"

echo "Installing $BIN $TAG ($TARGET)..."
curl -fsSL "$URL" -o "/tmp/$BIN"
chmod +x "/tmp/$BIN"

# Install — try without sudo first, fall back to sudo
if [ -w "$INSTALL_DIR" ]; then
  mkdir -p "$INSTALL_DIR"
  mv "/tmp/$BIN" "$INSTALL_DIR/$BIN"
else
  echo "Sudo required to install to $INSTALL_DIR"
  sudo mkdir -p "$INSTALL_DIR"
  sudo mv "/tmp/$BIN" "$INSTALL_DIR/$BIN"
fi

echo "$BIN installed to $INSTALL_DIR/$BIN"
$BIN --help 2>/dev/null || true
