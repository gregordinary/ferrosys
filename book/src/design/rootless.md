# Rootless and cross-platform

Building or reading an ext4 image with `ferrosys` needs no privilege and no
Linux-specific facility:

- **no mount** — the image is built and parsed as data, never mounted;
- **no loopback device, no FUSE** — nothing is attached to the kernel;
- **no root** — no privileged syscall is involved;
- **no C library** — the crate is pure Rust, with no `e2fsprogs` or libext2fs
  dependency to build or ship.

Because it depends on nothing kernel-specific, it builds and reads ext4 images on
Linux, macOS, Windows, and the BSDs alike. The same property makes it usable from
environments where a mount is simply not available.
