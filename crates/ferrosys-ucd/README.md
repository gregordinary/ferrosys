# ferrosys-ucd

The Unicode Character Database tables an APFS volume's names are compared with, as four
sorted constants. The `apfs` feature of [`ferrosys`](https://crates.io/crates/ferrosys)
depends on this crate, and computes from these tables the form a name is compared and hashed
as. The crate has one constant per table:

- `DECOMPOSITION`: every code point's full canonical decomposition
- `COMBINING_CLASS`: every nonzero canonical combining class
- `CASE_FOLDING`: every full case folding, statuses C and F
- `ASSIGNED`: every range of assigned code points, with the version that assigned it

Each is sorted by code point, so a lookup is a binary search:

```rust
let table = ferrosys_ucd::DECOMPOSITION;
let at = table.binary_search_by_key(&0xE9, |(cp, _)| *cp).expect("U+00E9 decomposes");
assert_eq!(table[at].1, &[0x65, 0x301]);
```

The tables are generated from Unicode 17.0.0's `UnicodeData.txt`, `CaseFolding.txt` and
`DerivedAge.txt`, whose SHA-256 digests the crate root records. The crate is `no_std` and
builds on Rust 1.88 or newer.

## License

<!-- prose-lint: off -- Rule 29 exempts legal boilerplate. -->

The tables are data from the Unicode Character Database, distributed under the Unicode
License v3. [LICENSE-UNICODE](LICENSE-UNICODE) carries its copyright and permission notice.
