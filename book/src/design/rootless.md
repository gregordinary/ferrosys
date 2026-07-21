# Rootless and cross-platform

`ferrosys` treats an ext2, ext3, or ext4 image as ordinary data: it builds and
parses the bytes directly, in the calling process, over any byte stream. That one
property is what makes it rootless and portable:

- **In userspace** — the image is constructed and parsed as a value in memory or
  a stream on disk, worked entirely within the process; the bytes are the whole
  interface.
- **Unprivileged** — working ordinary bytes needs an ordinary user account.
- **Self-contained** — pure Rust that links no system library, so it builds and
  ships as a single Rust dependency.

Because it depends on nothing kernel-specific, it builds and reads ext images on
Linux, macOS, Windows, and the BSDs alike — and works the same wherever mounting a
filesystem is not an option.
