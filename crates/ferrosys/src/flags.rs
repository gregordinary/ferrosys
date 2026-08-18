//! One shape for a newtype over a field of on-disk flag bits, in the two forms a word takes.
//!
//! Several structures in these formats carry a word whose bits are named, independent flags:
//! the three ext feature words, btrfs's three, an inode's `i_flags`, a FAT directory entry's
//! attribute byte. Each is a newtype over an integer, and each needs the same operations —
//! read the raw word, wrap one, test membership, test emptiness, add flags, remove flags.
//!
//! Written by hand, those come out slightly different every time — one type keeps the whole
//! set, the next drops emptiness, the one after that exposes its inner word where the rest
//! keep it private — and none of the differences means anything to a caller. So [`flag_set!`]
//! writes the operations, and every type has all of them and hides its word.
//!
//! # A word whose bits a caller names
//!
//! Some of those words are also a *vocabulary*: a person writes `extent` or `no-holes` on a
//! command line, a report prints the same word back, and the word has to mean one bit in both
//! directions. `named_flags!` is [`flag_set!`] plus that table — the flags and their names
//! declared once, and `names`, `from_name`, `unknown_bits` and a legible
//! [`Debug`](core::fmt::Debug) generated from it. It is written where a family whose format
//! has such a word is compiled, which is why the name here is not a link.
//!
//! A word nobody names takes [`flag_set!`] alone. An inode's flags and a directory entry's
//! attributes are read and written by this crate and by no user, so a table of names for them
//! would be a vocabulary with no speaker.
//!
//! # What is not a flag set
//!
//! [`AcceptedLoss`](crate::AcceptedLoss) is a set over bits and is deliberately not one of
//! these. Its element is a typed [`Property`](crate::Property) rather than another instance of
//! itself, so its operations take a `Property` — `and(Property)`, `contains(Property)` — and
//! `BitOr` between two sets is not the operation a caller wants. The numbering behind it is an
//! implementation detail nothing outside may depend on, which is the opposite of a flag word,
//! whose whole point is that the bits are the format's.

/// Generate the set operations for a newtype over a field of on-disk flag bits.
///
/// The type is declared by the caller, as a newtype over `$repr` with a **private** field:
/// the raw word is reached through [`bits`] and wrapped through [`from_bits`], so a caller
/// that means to read the on-disk value says so.
///
/// [`bits`]: #
/// [`from_bits`]: #
macro_rules! flag_set {
    ($name:ident: $repr:ty) => {
        impl $name {
            /// The empty set — no flags present.
            pub const NONE: Self = Self(0);

            /// The raw little-endian on-disk flag word.
            #[must_use]
            pub const fn bits(self) -> $repr {
                self.0
            }

            /// Wrap a raw on-disk flag word.
            ///
            /// Every bit is kept, including any this type does not name: what an image holds
            /// is what it holds, and a value narrowed on the way in would be reported as an
            /// image that does not carry a flag it does.
            #[must_use]
            pub const fn from_bits(bits: $repr) -> Self {
                Self(bits)
            }

            /// True when every flag set in `other` is also set in `self`.
            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            /// True when no flags are set.
            #[must_use]
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            /// `self` with every flag set in `other` cleared.
            #[must_use]
            pub const fn without(self, other: Self) -> Self {
                Self(self.0 & !other.0)
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }
    };
}

/// Generate a flag word whose bits carry names, from one table read in both directions.
///
/// The type is declared here as a newtype over `$repr` with a private field, carrying every
/// operation [`flag_set!`] writes, and each flag is declared beside the name it is known by
/// outside this crate:
///
/// ```ignore
/// named_flags! {
///     /// What the word is, and which decision it carries.
///     #[derive(Default)]
///     Incompat: u32 {
///         /// What setting this flag means for the on-disk form.
///         EXTENTS("extent") = 0x0040,
///     }
/// }
/// ```
///
/// One table carries both spellings, so neither can grow without the other. The Rust symbol
/// renders [`Debug`](core::fmt::Debug), which keeps a diagnostic legible without a lookup
/// table; the quoted name drives `names` and `from_name`, and is the vocabulary a person
/// types and the format's own tooling prints.
///
/// Attributes written above the type reach the declaration, so a word needing derives beyond
/// the four every one of them carries — a `Default`, a `Hash`, a `Serialize` behind a
/// feature — asks for them there.
///
/// # Which of the two vocabularies a word takes
///
/// A format usually spells its own flags twice: an all-capitals constant in the header that
/// defines it, and a lowercase option word its tooling accepts on a command line. The name in
/// this table is the one **this crate has to accept as input**, because a word a tool prints
/// and then refuses is the failure the single table exists to prevent — so where the two
/// spellings differ, the option word wins and a report prints it.
///
/// # This or [`named_choice!`](crate::naming::named_choice)
///
/// Both are one vocabulary read in both directions, and what separates them is the shape of
/// the value. A [`named_choice!`](crate::naming::named_choice) names the variants of a closed
/// set, exactly one of which holds at a time; this names the bits of a word, any number of
/// which are set at once. So a choice answers with one name and a word answers with a list,
/// and a word additionally has to answer for the bits it does *not* name — which a closed set
/// has no equivalent of, and which is why `unknown_bits` lives here.
// Compiled where a family whose format carries a *named* flag word is. Two of the four have
// one — a feature word a caller reads and writes — and the other two carry flag words nobody
// names, which is what `flag_set!` alone is for.
#[cfg(any(feature = "ext", feature = "btrfs"))]
macro_rules! named_flags {
    (
        $(#[$ty_meta:meta])*
        $name:ident: $repr:ty {
            $(
                $(#[$flag_doc:meta])*
                $flag:ident($word:literal) = $value:expr
            ),* $(,)?
        }
    ) => {
        $(#[$ty_meta])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name($repr);

        $crate::flags::flag_set!($name: $repr);

        impl $name {
            $(
                $(#[$flag_doc])*
                pub const $flag: Self = Self($value);
            )*

            /// The (Rust symbol, name, bit) table for every flag this type defines, in
            /// ascending bit order. It renders [`Debug`](core::fmt::Debug), resolves names,
            /// and detects bits outside the known set.
            const FLAGS: &'static [(&'static str, &'static str, $repr)] = &[
                $((stringify!($flag), $word, $value),)*
            ];

            /// The bits set in `self` that this type does not name — flags an implementation
            /// does not recognize.
            ///
            /// What a non-empty result means belongs to the word: on one that says the
            /// on-disk form differs, it is a filesystem that cannot be safely handled; on one
            /// that says a structure is merely present, it is a remark.
            #[must_use]
            pub const fn unknown_bits(self) -> $repr {
                let mut known: $repr = 0;
                let mut i = 0;
                while i < Self::FLAGS.len() {
                    known |= Self::FLAGS[i].2;
                    i += 1;
                }
                self.0 & !known
            }

            /// The names of the flags set in `self`, in ascending bit order — the words this
            /// type's own [`from_name`](Self::from_name) resolves.
            ///
            /// A bit this type does not name contributes no name;
            /// [`unknown_bits`](Self::unknown_bits) is what reports those, so a word carrying
            /// an unrecognized flag is never described as if it were understood.
            #[must_use]
            pub fn names(self) -> Vec<&'static str> {
                Self::FLAGS
                    .iter()
                    .filter(|(_, _, bit)| *bit != 0 && self.0 & bit == *bit)
                    .map(|(_, name, _)| *name)
                    .collect()
            }

            /// The single flag this word knows by `name`, or `None` when the name is not one
            /// of its own. The match is exact and lowercase, as the name is written and
            /// printed.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                Self::FLAGS
                    .iter()
                    .find(|(_, word, _)| *word == name)
                    .map(|(_, _, bit)| Self(*bit))
            }

            /// Every flag this word carries, appended to `out` as one comma-separated
            /// sentence: the named ones first, then a position for each bit no name covers,
            /// and `none` where the word is empty.
            ///
            /// This is the rendering a *message* wants — a refusal that has to say which
            /// features it is about, in a line a person reads. A report listing features in
            /// a column of their own wants [`names`](Self::names) and
            /// [`unknown_bits`](Self::unknown_bits) separately instead.
            ///
            /// A bit with no name is never dropped: a word carrying a feature a later
            /// release of the format defines is exactly the word a refusal must not be
            /// silent about, and one rendered as its position can at least be looked up.
            pub fn describe(self, out: &mut String) {
                let mut first = true;
                let mut separate = |out: &mut String| {
                    if !first {
                        out.push_str(", ");
                    }
                    first = false;
                };
                for name in self.names() {
                    separate(out);
                    out.push_str(name);
                }
                let unknown = self.unknown_bits();
                for bit in 0..<$repr>::BITS {
                    if unknown & ((1 as $repr) << bit) != 0 {
                        separate(out);
                        out.push_str(&format!("bit {bit}"));
                    }
                }
                if first {
                    out.push_str("none");
                }
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                let mut first = true;
                for (symbol, _, bit) in Self::FLAGS {
                    if self.0 & bit == *bit && *bit != 0 {
                        if !first {
                            write!(f, " | ")?;
                        }
                        write!(f, "{symbol}")?;
                        first = false;
                    }
                }
                let unknown = self.unknown_bits();
                if unknown != 0 {
                    if !first {
                        write!(f, " | ")?;
                    }
                    write!(f, "{unknown:#x}")?;
                    first = false;
                }
                if first {
                    write!(f, "NONE")?;
                }
                write!(f, ")")
            }
        }
    };
}

pub(crate) use flag_set;
#[cfg(any(feature = "ext", feature = "btrfs"))]
pub(crate) use named_flags;
