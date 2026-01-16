#!/bin/bash
set -e

COMMIT="6c79dfb9a31e2fdde6230da4edcb71cc082ca7d9"
REPO="https://github.com/zydou/arti"
PATCH_FILE="arti-patches.patch"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP="/tmp/arti-$$"

echo "Cloning Arti at $COMMIT..."
rm -rf "$TEMP"
git clone "$REPO" "$TEMP" 2>&1 | grep -v "warning:" || true
cd "$TEMP"
git checkout "$COMMIT"

echo "Converting symlinks to files..."
find . -type l -print0 | while IFS= read -r -d '' link; do
  target=$(readlink "$link")
  dir=$(dirname "$link")
  resolved=$(cd "$dir" && readlink -f "$target" 2>/dev/null) || continue
  if [ -f "$resolved" ]; then
    rm "$link"
    cp "$resolved" "$link"
  fi
done

echo "Moving to vendor/arti..."
rm -rf "${SCRIPT_DIR}/vendor/arti"
mv "$TEMP" "${SCRIPT_DIR}/vendor/arti"

echo "Applying patch..."
cd "$SCRIPT_DIR"
git apply "${PATCH_FILE}"

echo "Done!"
