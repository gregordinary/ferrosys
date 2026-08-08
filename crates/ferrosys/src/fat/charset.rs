//! How a short name's bytes above ASCII are read: [`ShortNameCharset`], and the OEM code
//! pages it names.
//!
//! An eleven-byte short name is a sequence of bytes in whatever code page the machine that
//! created the entry was running under. **Nothing in a FAT volume records which one.**
//! `BS_OEMName` at offset 3 of the boot sector names the *formatter* — `MSWIN4.1`,
//! `mkfs.fat`, `FRDOS5.1` — and the format's own specification says an implementation must
//! never interpret it. Worse, the code page was a property of the machine and the moment
//! each name was created rather than of the volume, so one directory may legitimately hold
//! names written under two of them.
//!
//! So the page is an input and is never guessed. [`Verbatim`](ShortNameCharset::Verbatim),
//! the default, hands the bytes back exactly as they sit on disk; naming a page interprets
//! them. A scan reports every distinct byte above ASCII it saw across the image, which is
//! evidence a person can act on rather than an inference this crate is in a position to
//! make.
//!
//! # What is not here
//!
//! **The double-byte pages** — Shift-JIS, GBK, Big5 and their relatives. Those are not
//! 128-entry tables: a lead byte selects a second table for the byte that follows, so
//! reading one is a state machine over the name rather than a lookup per byte. A caller
//! holding such an image reads it under [`Verbatim`](ShortNameCharset::Verbatim) and
//! transcodes the bytes it gets back.
//!
//! **Long names.** A long name is a sequence of UTF-16 code units, which is unambiguous, so
//! there is nothing about it for a caller to steer. This applies to the eleven-byte short
//! name field alone — and to the volume label, which is that same field.
//!
//! This module is pure: it maps bytes to characters and performs no I/O.

/// How the bytes of a short name above ASCII are interpreted.
///
/// Bytes below `0x80` are ASCII under every value here, which is the whole of what this
/// crate's own writer emits — a character it cannot represent in a short name becomes an
/// underscore, and the name it was given is kept in the long-name entries. So a value other
/// than [`Verbatim`](Self::Verbatim) only ever changes how an image *somebody else* wrote
/// reads back.
///
/// The enum is `#[non_exhaustive]`: a page added later is not a breaking change, and
/// [`Custom`](Self::Custom) means a caller need not wait for one.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum ShortNameCharset {
    /// Hand the bytes back exactly as they sit on disk, interpreting nothing.
    ///
    /// The default, and the only value that invents nothing: the image does not record its
    /// code page, so any other value is a claim the caller is making rather than one the
    /// bytes support. A name read this way is a byte string that may not be UTF-8, which is
    /// what a path on a POSIX host is anyway.
    #[default]
    Verbatim,
    /// IBM code page 437: the original IBM PC character set, and the OEM default in the
    /// United States. The one to reach for when an image says nothing else about itself.
    Cp437,
    /// IBM code page 850, "Latin-1 multilingual": the DOS page across Western Europe.
    Cp850,
    /// IBM code page 852, "Latin-2": the DOS page across Central Europe.
    Cp852,
    /// IBM code page 865, "Nordic": [`Cp437`](Self::Cp437) with three positions changed.
    Cp865,
    /// IBM code page 866: the DOS page for Cyrillic.
    Cp866,
    /// Any other single-byte page, as the characters bytes `0x80` through `0xFF` stand for,
    /// in order.
    ///
    /// The reference is `'static` so that [`ShortNameCharset`] stays `Copy` and
    /// [`OpenOptions`](super::OpenOptions) grows no lifetime parameter; a `const` table in
    /// the caller's own crate satisfies it.
    ///
    /// ```
    /// use ferrosys::fat::ShortNameCharset;
    ///
    /// // ISO 8859-1, where the byte and the code point are the same number.
    /// const LATIN1: [char; 128] = {
    ///     let mut table = ['\0'; 128];
    ///     let mut i = 0;
    ///     while i < 128 {
    ///         // A `u8` in 0x80..=0xFF is always a code point, so the conversion is total.
    ///         table[i] = (0x80 + i as u32) as u8 as char;
    ///         i += 1;
    ///     }
    ///     table
    /// };
    /// let charset = ShortNameCharset::Custom(&LATIN1);
    /// assert_eq!(charset.decode(&[b'A', 0xE9]), "Aé".as_bytes());
    /// ```
    Custom(&'static [char; 128]),
}

impl ShortNameCharset {
    /// The characters bytes `0x80` through `0xFF` stand for, or `None` under
    /// [`Verbatim`](Self::Verbatim), which interprets nothing.
    #[must_use]
    pub const fn table(self) -> Option<&'static [char; 128]> {
        match self {
            ShortNameCharset::Verbatim => None,
            ShortNameCharset::Cp437 => Some(&CP437),
            ShortNameCharset::Cp850 => Some(&CP850),
            ShortNameCharset::Cp852 => Some(&CP852),
            ShortNameCharset::Cp865 => Some(&CP865),
            ShortNameCharset::Cp866 => Some(&CP866),
            ShortNameCharset::Custom(table) => Some(table),
        }
    }

    /// The lowercase name of this charset, for a rendered report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ShortNameCharset::Verbatim => "verbatim",
            ShortNameCharset::Cp437 => "cp437",
            ShortNameCharset::Cp850 => "cp850",
            ShortNameCharset::Cp852 => "cp852",
            ShortNameCharset::Cp865 => "cp865",
            ShortNameCharset::Cp866 => "cp866",
            ShortNameCharset::Custom(_) => "custom",
        }
    }

    /// `name` as the bytes a caller receives: ASCII passed through, and everything above it
    /// either passed through unchanged or replaced by the UTF-8 encoding of the character
    /// this charset gives it.
    ///
    /// Under [`Verbatim`](Self::Verbatim) the output is the input.
    #[must_use]
    pub fn decode(self, name: &[u8]) -> Vec<u8> {
        let Some(table) = self.table() else {
            return name.to_vec();
        };
        let mut out = Vec::with_capacity(name.len());
        let mut buf = [0u8; 4];
        for &byte in name {
            if byte < 0x80 {
                out.push(byte);
            } else {
                out.extend_from_slice(table[byte as usize - 0x80].encode_utf8(&mut buf).as_bytes());
            }
        }
        out
    }
}

/// Code page 437, as bytes `0x80` through `0xFF`.
///
/// Transcribed rather than derived, so the tests below pin the positions a transposition
/// would move: the accented run at the start, the box-drawing block, and the Greek run.
#[rustfmt::skip]
const CP437: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ',
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐',
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧',
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩',
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{A0}',
];

/// Code page 850, as bytes `0x80` through `0xFF`.
#[rustfmt::skip]
const CP850: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', 'ø', '£', 'Ø', '×', 'ƒ',
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '®', '¬', '½', '¼', '¡', '«', '»',
    '░', '▒', '▓', '│', '┤', 'Á', 'Â', 'À', '©', '╣', '║', '╗', '╝', '¢', '¥', '┐',
    '└', '┴', '┬', '├', '─', '┼', 'ã', 'Ã', '╚', '╔', '╩', '╦', '╠', '═', '╬', '¤',
    'ð', 'Ð', 'Ê', 'Ë', 'È', 'ı', 'Í', 'Î', 'Ï', '┘', '┌', '█', '▄', '¦', 'Ì', '▀',
    'Ó', 'ß', 'Ô', 'Ò', 'õ', 'Õ', 'µ', 'þ', 'Þ', 'Ú', 'Û', 'Ù', 'ý', 'Ý', '¯', '´',
    '\u{AD}', '±', '‗', '¾', '¶', '§', '÷', '¸', '°', '¨', '·', '¹', '³', '²', '■', '\u{A0}',
];

/// Code page 852, as bytes `0x80` through `0xFF`.
#[rustfmt::skip]
const CP852: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'ů', 'ć', 'ç', 'ł', 'ë', 'Ő', 'ő', 'î', 'Ź', 'Ä', 'Ć',
    'É', 'Ĺ', 'ĺ', 'ô', 'ö', 'Ľ', 'ľ', 'Ś', 'ś', 'Ö', 'Ü', 'Ť', 'ť', 'Ł', '×', 'č',
    'á', 'í', 'ó', 'ú', 'Ą', 'ą', 'Ž', 'ž', 'Ę', 'ę', '¬', 'ź', 'Č', 'ş', '«', '»',
    '░', '▒', '▓', '│', '┤', 'Á', 'Â', 'Ě', 'Ş', '╣', '║', '╗', '╝', 'Ż', 'ż', '┐',
    '└', '┴', '┬', '├', '─', '┼', 'Ă', 'ă', '╚', '╔', '╩', '╦', '╠', '═', '╬', '¤',
    'đ', 'Đ', 'Ď', 'Ë', 'ď', 'Ň', 'Í', 'Î', 'ě', '┘', '┌', '█', '▄', 'Ţ', 'Ů', '▀',
    'Ó', 'ß', 'Ô', 'Ń', 'ń', 'ň', 'Š', 'š', 'Ŕ', 'Ú', 'ŕ', 'Ű', 'ý', 'Ý', 'ţ', '´',
    '\u{AD}', '˝', '˛', 'ˇ', '˘', '§', '÷', '¸', '°', '¨', '˙', 'ű', 'Ř', 'ř', '■', '\u{A0}',
];

/// Code page 865, which is [`CP437`] with three positions changed.
///
/// Built from that table rather than transcribed beside it: the three differences are the
/// whole of what distinguishes the two, and writing out the other 125 again would be 125
/// more chances to differ by accident.
const CP865: [char; 128] = {
    let mut table = CP437;
    table[0x9B - 0x80] = 'ø';
    table[0x9D - 0x80] = 'Ø';
    table[0xAF - 0x80] = '¤';
    table
};

/// Code page 866, as bytes `0x80` through `0xFF`.
///
/// Four fifths of it is arithmetic: the Cyrillic alphabet occupies three contiguous runs in
/// Unicode and in this page alike, and the box-drawing block is [`CP437`]'s exactly. Only
/// the sixteen bytes from `0xF0` are transcribed, so the transcription surface is a sixth of
/// what writing the table out would be.
const CP866: [char; 128] = {
    let mut table = ['\0'; 128];
    let mut i = 0;
    // 0x80..=0x9F: А through Я, U+0410 through U+042F.
    while i < 32 {
        // Every value here is a Cyrillic code point, so the conversion is total; the
        // fallback stands only because `const` has no `expect`.
        table[i] = match char::from_u32(0x0410 + i as u32) {
            Some(c) => c,
            None => '\u{FFFD}',
        };
        i += 1;
    }
    // 0xA0..=0xAF: а through п, U+0430 through U+043F.
    while i < 48 {
        table[i] = match char::from_u32(0x0430 + (i - 32) as u32) {
            Some(c) => c,
            None => '\u{FFFD}',
        };
        i += 1;
    }
    // 0xB0..=0xDF: the box-drawing block, identical to code page 437's.
    while i < 96 {
        table[i] = CP437[i];
        i += 1;
    }
    // 0xE0..=0xEF: р through я, U+0440 through U+044F.
    while i < 112 {
        table[i] = match char::from_u32(0x0440 + (i - 96) as u32) {
            Some(c) => c,
            None => '\u{FFFD}',
        };
        i += 1;
    }
    // 0xF0..=0xFF: the tail, which follows no run.
    let tail = [
        'Ё', 'ё', 'Є', 'є', 'Ї', 'ї', 'Ў', 'ў', '°', '∙', '·', '√', '№', '¤', '■', '\u{A0}',
    ];
    let mut j = 0;
    while j < 16 {
        table[112 + j] = tail[j];
        j += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_interprets_nothing() {
        // The default hands back what it was given, byte for byte, including a byte that is
        // not valid UTF-8 on its own. This is the property that makes it safe to read an
        // image whose page is unknown: nothing is invented.
        let charset = ShortNameCharset::default();
        assert_eq!(charset, ShortNameCharset::Verbatim);
        assert!(charset.table().is_none());
        for name in [&b"README  TXT"[..], b"CAF\x82    TXT", b"\xFF\xFE\x00"] {
            assert_eq!(charset.decode(name), name);
        }
    }

    #[test]
    fn every_table_is_a_page_and_ascii_is_untouched() {
        for charset in [
            ShortNameCharset::Cp437,
            ShortNameCharset::Cp850,
            ShortNameCharset::Cp852,
            ShortNameCharset::Cp865,
            ShortNameCharset::Cp866,
        ] {
            let table = charset.table().expect("a named page has a table");
            // A page maps every byte above ASCII to something, and to something that is not
            // the null character — which is what an unfilled slot in a table built by a
            // const loop would be.
            assert!(
                table.iter().all(|&c| c != '\0'),
                "{}: a table position was left unfilled",
                charset.as_str()
            );
            // Bytes below 0x80 never reach a table, so an 8.3 name of ASCII reads back as
            // itself under every page.
            assert_eq!(charset.decode(b"README  TXT"), b"README  TXT");
        }
    }

    #[test]
    fn code_page_437_is_where_its_landmarks_are() {
        // Landmarks rather than the whole table: a transposition anywhere in a run moves
        // the run's ends, and each of these sits at a boundary a transposition would cross.
        let t = ShortNameCharset::Cp437.table().unwrap();
        assert_eq!(t[0x80 - 0x80], 'Ç', "the first accented character");
        assert_eq!(t[0x9F - 0x80], 'ƒ', "the last before the second run");
        assert_eq!(t[0xA0 - 0x80], 'á');
        assert_eq!(t[0xB0 - 0x80], '░', "the box-drawing block begins");
        assert_eq!(t[0xDF - 0x80], '▀', "and ends");
        assert_eq!(t[0xE0 - 0x80], 'α', "the Greek run begins");
        assert_eq!(t[0xE1 - 0x80], 'ß', "which is not all Greek");
        assert_eq!(t[0xFF - 0x80], '\u{A0}', "a no-break space, not a space");
        // The peseta sign is the one character in the page outside Latin-1 and the box
        // drawings, and it is the position most easily lost.
        assert_eq!(t[0x9E - 0x80], '\u{20A7}');
    }

    #[test]
    fn code_page_865_differs_from_437_in_exactly_three_positions() {
        // Derived from 437 rather than transcribed beside it, so this asserts the
        // derivation is the three changes the page actually makes and nothing else.
        let a = ShortNameCharset::Cp437.table().unwrap();
        let b = ShortNameCharset::Cp865.table().unwrap();
        let differ: Vec<usize> = (0..128).filter(|&i| a[i] != b[i]).collect();
        assert_eq!(differ, vec![0x9B - 0x80, 0x9D - 0x80, 0xAF - 0x80]);
        assert_eq!(b[0x9B - 0x80], 'ø');
        assert_eq!(b[0x9D - 0x80], 'Ø');
        assert_eq!(b[0xAF - 0x80], '¤');
    }

    #[test]
    fn code_page_866_holds_the_cyrillic_alphabet_in_order() {
        // The three runs are generated, so what is worth asserting is that they are the
        // right runs at the right offsets and that the box block between them was copied
        // rather than overwritten.
        let t = ShortNameCharset::Cp866.table().unwrap();
        let upper: String = (0x80..0xB0).map(|b| t[b - 0x80]).collect();
        assert_eq!(upper, "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп");
        let lower: String = (0xE0..0xF0).map(|b| t[b - 0x80]).collect();
        assert_eq!(lower, "рстуфхцчшщъыьэюя");
        assert_eq!(t[0xB0 - 0x80], '░', "the box block is 437's");
        assert_eq!(t[0xDF - 0x80], '▀');
        assert_eq!(t[0xF0 - 0x80], 'Ё', "the tail follows no run");
        assert_eq!(t[0xFC - 0x80], '№');
    }

    #[test]
    fn the_latin_pages_agree_where_they_agree_and_differ_where_they_differ() {
        // 850 and 852 share 437's first sixteen positions and part its ways after — which
        // is the property that makes naming the wrong one produce a wrong name rather than
        // an obviously broken one, and the reason the page is an input.
        let (a, b, c) = (
            ShortNameCharset::Cp437.table().unwrap(),
            ShortNameCharset::Cp850.table().unwrap(),
            ShortNameCharset::Cp852.table().unwrap(),
        );
        for i in 0..5 {
            assert_eq!(a[i], b[i]);
            assert_eq!(a[i], c[i]);
        }
        // Byte 0x85 is `à` in 437 and 850 and `ů` in 852: one byte, three pages, two
        // answers.
        assert_eq!(a[0x85 - 0x80], 'à');
        assert_eq!(b[0x85 - 0x80], 'à');
        assert_eq!(c[0x85 - 0x80], 'ů');
        // And 850's Latin-1 supplement, which 437 spends on box drawing.
        assert_eq!(b[0xE1 - 0x80], 'ß');
        assert_eq!(b[0xD0 - 0x80], 'ð');
        assert_eq!(a[0xD0 - 0x80], '╨');
    }

    #[test]
    fn a_name_decodes_to_the_utf8_of_its_page() {
        // The whole point, end to end: the same eleven bytes read as three different names.
        let name = b"CAF\x82    TXT";
        assert_eq!(
            ShortNameCharset::Cp437.decode(name),
            "CAFé    TXT".as_bytes()
        );
        assert_eq!(
            ShortNameCharset::Cp850.decode(name),
            "CAFé    TXT".as_bytes()
        );
        assert_eq!(
            ShortNameCharset::Cp866.decode(name),
            "CAFВ    TXT".as_bytes()
        );
        // A character outside Latin-1 encodes to three bytes, so the decoded name is longer
        // than the field it came from — which is why a decoded name is a `Vec` rather than
        // an array.
        assert_eq!(ShortNameCharset::Cp437.decode(b"\x9E"), "₧".as_bytes());
        assert_eq!(ShortNameCharset::Cp437.decode(b"\x9E").len(), 3);
    }

    #[test]
    fn a_custom_page_is_reached_without_a_release() {
        const LATIN1: [char; 128] = {
            let mut table = ['\0'; 128];
            let mut i = 0;
            while i < 128 {
                table[i] = (0x80 + i as u32) as u8 as char;
                i += 1;
            }
            table
        };
        let charset = ShortNameCharset::Custom(&LATIN1);
        assert_eq!(charset.as_str(), "custom");
        assert_eq!(charset.decode(&[b'A', 0xE9]), "Aé".as_bytes());
        // And it is `Copy`, which is what keeps `OpenOptions` `Copy` and free of a lifetime.
        let copy = charset;
        assert_eq!(copy, charset);
    }
}
