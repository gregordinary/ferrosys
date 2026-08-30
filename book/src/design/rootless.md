# Rootless and cross-platform

`ferrosys` treats a filesystem image as ordinary data, in every family it carries. It
builds and parses the bytes directly, in the calling process, over any byte stream. That
one property is what makes it rootless and portable:

- **In userspace.** The image is a value in memory or a stream on disk, and the process
  works it end to end. The bytes are the whole interface.
- **Unprivileged.** Working ordinary bytes needs an ordinary user account.
- **Self-contained.** Pure Rust throughout, so it builds and ships as one Rust
  dependency.

The byte layer is the same code on every platform. It builds and reads images on Linux,
macOS, Windows, and the BSDs alike, and it works the same where mounting is unavailable.
That holds for every family. ferrosys writes and reads a FAT32 boot partition, an exFAT
card image, and a btrfs volume with subvolumes. The host kernel needs no driver for any
of them, exactly as with an ext4 rootfs.

The one exception is the `dir` feature, and it is an exception by nature. Walking a host
tree means reading that host's inode metadata and extended attributes, which a portable
byte-level format cannot abstract over. It is present on Linux. Everything else is the
same code everywhere: the formatter, the reader, the scan, the archive source and sink.

Rootlessness has a consequence for the directory walk. An unprivileged build cannot own
the files it stages as root, so the tree it walks records the building user's ids.
`DirectorySource::owner` puts the intended ownership into the image, and
`format --owner 0:0` does the same on the command line. Both work unprivileged.
