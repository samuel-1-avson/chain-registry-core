#!/usr/bin/env bash
# Build minimal rootfs images for each ecosystem and export their filesystem
# layers into config/sandbox/rootfs/{ecosystem}/.
#
# Usage:
#   cd chain-registry/
#   bash config/sandbox/rootfs/build-rootfs.sh
#
# After running, each rootfs/ subdirectory contains a minimal filesystem tree
# suitable for nsjail --chroot.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTFS_DIR="$SCRIPT_DIR"

ECOSYSTEMS=("npm" "pip" "cargo" "rubygems" "maven")

for eco in "${ECOSYSTEMS[@]}"; do
    echo "=== Building rootfs for: $eco ==="
    DOCKERFILE="$ROOTFS_DIR/Dockerfile.$eco"
    IMAGE_TAG="creg-rootfs-$eco:latest"
    DEST="$ROOTFS_DIR/$eco"

    if [ ! -f "$DOCKERFILE" ]; then
        echo "  SKIP: No Dockerfile found at $DOCKERFILE"
        continue
    fi

    # Build the image
    docker build -t "$IMAGE_TAG" -f "$DOCKERFILE" "$ROOTFS_DIR"

    # Export the filesystem into a directory
    rm -rf "$DEST"
    mkdir -p "$DEST"

    CONTAINER_ID=$(docker create "$IMAGE_TAG")
    docker export "$CONTAINER_ID" | tar -xf - -C "$DEST"
    docker rm "$CONTAINER_ID" >/dev/null

    echo "  Rootfs for $eco exported to $DEST ($(du -sh "$DEST" | awk '{print $1}'))"
done

echo ""
echo "All rootfs images built. Point nsjail at:"
for eco in "${ECOSYSTEMS[@]}"; do
    echo "  --chroot $ROOTFS_DIR/$eco/"
done
