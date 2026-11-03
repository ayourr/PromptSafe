#!/bin/sh
# Install PromptSafe on Linux:
#   curl -fsSL https://github.com/ayourr/PromptSafe/releases/latest/download/install.sh | sh
# Options (environment variables):
#   PROMPTSAFE_VERSION=v0.2.0   install a given version instead of the latest
#   PROMPTSAFE_DIR=~/bin        install into this folder
set -eu

repo="ayourr/PromptSafe"
version="${PROMPTSAFE_VERSION:-latest}"

case "$(uname -s)" in
  Linux) os=linux ;;
  *) echo "promptsafe: this installer is for Linux; on Windows use install.ps1" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "promptsafe: unsupported CPU $(uname -m)" >&2; exit 1 ;;
esac

if [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi
base="${PROMPTSAFE_BASE_URL:-$base}"  # mirror or local test server
file="promptsafe-$os-$arch"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  else wget -qO "$2" "$1"; fi
}
echo "Downloading $file ($version)..."
fetch "$base/$file" "$tmp/promptsafe"
fetch "$base/checksums.txt" "$tmp/checksums.txt"

want="$(grep " $file\$" "$tmp/checksums.txt" | cut -d' ' -f1)"
got="$(sha256sum "$tmp/promptsafe" | cut -d' ' -f1)"
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "promptsafe: checksum mismatch, not installing" >&2
  exit 1
fi
chmod +x "$tmp/promptsafe"

dir="${PROMPTSAFE_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin
  elif command -v sudo >/dev/null 2>&1; then dir=/usr/local/bin; use_sudo=1
  else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir" 2>/dev/null || true
if [ "${use_sudo:-0}" = 1 ]; then
  sudo install -m 0755 "$tmp/promptsafe" "$dir/promptsafe"
else
  install -m 0755 "$tmp/promptsafe" "$dir/promptsafe"
fi

echo "Installed $("$dir/promptsafe" version 2>/dev/null || echo promptsafe) to $dir/promptsafe"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run 'promptsafe' from anywhere." ;;
esac
