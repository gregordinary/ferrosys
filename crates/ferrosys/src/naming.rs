//! One table per named choice, read in both directions.
//!
//! A closed set of variants that a caller *names* — on a command line, in a configuration
//! file — has three things to say about itself: the word each variant is written as, the
//! whole list of them for a message that offers the choice, and which variant a word means.
//! Written by hand those are three places one vocabulary lives, and the failure they invite
//! is silent: a variant added to two of them leaves a tool that prints a word it refuses, or
//! offers a list it does not accept.
//!
//! [`named_choice!`] generates all three from one table. The `as_str` arm it writes is an
//! exhaustive `match`, so a variant added to the enum and not to the table does not compile.
//!
//! This is for the choices a caller names. A variant that is only ever *rendered* — the
//! subsystem a finding was filed under, the direction a fidelity record runs — has one
//! projection and one site to edit, and spells it as an ordinary `match`.

/// A closed set of variants a caller names, in whichever direction it is being read.
///
/// Every type carrying this offers exactly the words it accepts: [`NAMES`](Self::NAMES) is
/// the list, [`as_str`](Self::as_str) writes one, and [`from_name`](Self::from_name) reads
/// one back. So a name a report prints can be typed straight into whatever takes one, and a
/// consumer building an argument parser writes one function for every choice this crate has
/// rather than one per choice.
///
/// Each implementor also carries the same three as inherent items, so reaching them does not
/// require this trait in scope. It is here for the caller that wants them generically.
pub trait NamedChoice: Copy + Sized + 'static {
    /// Every variant, in the order a message offering the choice lists them.
    const NAMES: &'static [Self];

    /// This variant's name.
    fn as_str(self) -> &'static str;

    /// The variant `name` names, or `None` where it names none.
    fn from_name(name: &str) -> Option<Self>;
}

/// Generate `as_str`, `NAMES`, and `from_name` for a closed set of named variants, as
/// inherent items and as a [`NamedChoice`] implementation.
///
/// The table is the whole vocabulary. `NAMES` lists the variants in the order written here,
/// which is the order a message offering the choice lists them, and `from_name` accepts
/// exactly the words `as_str` writes.
macro_rules! named_choice {
    (
        $ty:ty {
            $($variant:path => $name:literal),* $(,)?
        }
    ) => {
        impl $ty {
            /// Every variant this type names, in the order a message offering the choice
            /// lists them.
            pub const NAMES: &'static [Self] = &[$($variant),*];

            /// This variant's name — the word it is written as wherever one is written.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($variant => $name),*
                }
            }

            /// The variant `name` names, or `None` where it names none.
            ///
            /// Exactly the inverse of [`as_str`](Self::as_str): the words accepted are the
            /// words written, and neither list can grow without the other.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    $($name => Some($variant),)*
                    _ => None,
                }
            }
        }

        impl $crate::naming::NamedChoice for $ty {
            const NAMES: &'static [Self] = Self::NAMES;

            fn as_str(self) -> &'static str {
                Self::as_str(self)
            }

            fn from_name(name: &str) -> Option<Self> {
                Self::from_name(name)
            }
        }
    };
}

pub(crate) use named_choice;

/// Serialize a type as the word its `as_str` writes.
///
/// A variant's name in Rust is not a word this crate says anywhere else: `ExFat` is written
/// `exfat`, `ChangeTime` is written `change time`, `GroupDescriptor` is written
/// `group descriptor`. A derived `Serialize` emits the Rust name, which puts a second
/// spelling of the same vocabulary on a public surface for no one's benefit -- a consumer
/// embedding one of these values in its own document then reads a word this crate prints
/// nowhere. This writes the one word instead, from the one table that holds it.
///
/// Expands to nothing without the `serde` feature, so a caller writes it beside the type
/// unconditionally.
macro_rules! serialize_as_name {
    ($ty:ty) => {
        #[cfg(feature = "serde")]
        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }
    };
}

pub(crate) use serialize_as_name;

#[cfg(test)]
mod tests {
    use super::NamedChoice;
    use crate::Severity;

    #[test]
    fn a_named_choice_writes_exactly_the_names_it_reads() {
        // The property the macro exists for, checked on one implementor: every name the
        // list offers parses back to the variant that wrote it, and nothing else parses at
        // all. A variant missing from the table cannot reach here — the generated `as_str`
        // is an exhaustive match, so it would not compile.
        for &choice in <Severity as NamedChoice>::NAMES {
            assert_eq!(Severity::from_name(choice.as_str()), Some(choice));
        }
        assert_eq!(Severity::from_name("Cosmetic"), None);
        assert_eq!(Severity::from_name(""), None);
        // The order is the order the scale runs in, which is what a message listing the
        // choice offers and what a threshold reads.
        assert_eq!(
            Severity::NAMES
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            ["cosmetic", "conformance", "integrity", "structural"]
        );
    }
}
