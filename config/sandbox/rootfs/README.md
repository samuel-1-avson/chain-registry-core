# Chain Registry Sandbox — Minimal Rootfs Images
#
# These Dockerfiles produce minimal filesystem images for nsjail chroot.
# They contain ONLY the tools needed for package install validation.
#
# Build all rootfs images:
#   ./build-rootfs.sh
#
# The resulting rootfs directories are:
#   rootfs/npm/       — Node.js + npm
#   rootfs/pip/       — Python + pip
#   rootfs/cargo/     — Rust + cargo
#   rootfs/rubygems/  — Ruby + gem
#   rootfs/maven/     — Java + Maven

## Usage
#
# After building, the validator loads the appropriate rootfs based on the
# package's ecosystem, passing `--chroot config/sandbox/rootfs/{ecosystem}/`
# to nsjail instead of `--chroot /`.
