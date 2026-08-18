# Rootless and cross-platform

`ferrosys` treats a filesystem image as ordinary data, in every family it carries:
it builds and parses the bytes directly, in the calling process, over any byte
stream. That one property is what makes it rootless and portable:

- **In userspace** — the image is constructed and parsed as a value in memory or
  a stream on disk, worked entirely within the process; the bytes are the whole
  interface.
- **Unprivileged** — working ordinary bytes needs an ordinary user account.
- **Self-contained** — pure Rust that links no system library, so it builds and
  ships as a single Rust dependency.

Because it depends on nothing kernel-specific, it builds and reads images on
Linux, macOS, Windows, and the BSDs alike — and works the same wherever mounting a
filesystem is not an option. That holds for every family: a FAT32 boot partition,
an exFAT card image, and a btrfs volume with subvolumes in it are each written and
read on a host whose kernel has no driver for them, the same way an ext4 rootfs is.

The one exception is the `dir` feature, and it is an exception by nature rather than by
omission: walking a host tree means reading that host's inode metadata and extended
attributes, which is the one thing a portable byte-level format cannot abstract over. It
is present on Linux. Everything else — the formatter, the reader, the scan, the archive
source and sink — is the same code everywhere.

Rootlessness has a consequence worth stating for the directory walk in particular. An
unprivileged build cannot own the files it stages as root, so the tree it walks records
the building user's ids; `DirectorySource::owner` (and `format --owner 0:0` on the command
line) is what puts the intended ownership into the image without any privilege at all.
