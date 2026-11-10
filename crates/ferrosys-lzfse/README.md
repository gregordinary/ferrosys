# ferrosys-lzfse

LZVN and LZFSE decoders in safe Rust. They are two of the encodings an APFS compressed file
keeps its content in. The `lzvn` and `lzfse` features of
[`ferrosys`](https://crates.io/crates/ferrosys) compile this crate.

Each decoder undoes one stream into a buffer the caller sizes, and reports how many bytes it
produced. The buffer bounds the work. A stream that expands past it is refused, and nothing is
allocated on the strength of a length the stream declares.

```rust
// An LZVN stream: a literal of five bytes, then the end-of-stream instruction.
let stream = [0xE5, b'h', b'e', b'l', b'l', b'o', 0x06, 0, 0, 0, 0, 0, 0, 0];
let mut out = [0u8; 16];
let produced = ferrosys_lzfse::decompress_lzvn(&stream, &mut out).expect("a well-formed stream");
assert_eq!(&out[..produced], b"hello");
```

The crate builds on Rust 1.88 or newer.

## License

<!-- prose-lint: off -- Rule 29 exempts legal boilerplate. -->

The decoders are derived from the ones in Apple's lzfse project, and are distributed under
its BSD-3-Clause license. [LICENSE](LICENSE) carries the license text and its copyright
notices.
