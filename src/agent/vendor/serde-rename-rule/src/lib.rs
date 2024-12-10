//! Serde RenameRule. [Extract from](https://github.com/serde-rs/serde/blob/v1.0.126/serde_derive/src/internals/case.rs)
//!
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

//
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RenameRule {
    /// Rename direct children to "lowercase" style.
    LowerCase,
    /// Rename direct children to "UPPERCASE" style.
    UpperCase,
    /// Rename direct children to "PascalCase" style, as typically used for
    /// enum variants.
    PascalCase,
    /// Rename direct children to "camelCase" style.
    CamelCase,
    /// Rename direct children to "snake_case" style, as commonly used for
    /// fields.
    SnakeCase,
    /// Rename direct children to "SCREAMING_SNAKE_CASE" style, as commonly
    /// used for constants.
    ScreamingSnakeCase,
    /// Rename direct children to "kebab-case" style.
    KebabCase,
    /// Rename direct children to "SCREAMING-KEBAB-CASE" style.
    ScreamingKebabCase,
}

static RENAME_RULES: &[(&str, RenameRule)] = &[
    ("lowercase", RenameRule::LowerCase),
    ("UPPERCASE", RenameRule::UpperCase),
    ("PascalCase", RenameRule::PascalCase),
    ("camelCase", RenameRule::CamelCase),
    ("snake_case", RenameRule::SnakeCase),
    ("SCREAMING_SNAKE_CASE", RenameRule::ScreamingSnakeCase),
    ("kebab-case", RenameRule::KebabCase),
    ("SCREAMING-KEBAB-CASE", RenameRule::ScreamingKebabCase),
];

impl RenameRule {
    pub fn from_rename_all_str(s: &str) -> Result<Self, ParseError> {
        for (name, rule) in RENAME_RULES {
            if s == *name {
                return Ok(*rule);
            }
        }
        Err(ParseError::Unknown(s.into()))
    }
    pub fn to_rename_all_str(&self) -> &'static str {
        for (name, rule) in RENAME_RULES {
            if rule == self {
                return name;
            }
        }
        unreachable!()
    }

    /// Apply a renaming rule to an enum variant, returning the version expected in the source.
    pub fn apply_to_variant(&self, variant: &str) -> String {
        match *self {
            Self::PascalCase => variant.into(),
            Self::LowerCase => variant.to_ascii_lowercase(),
            Self::UpperCase => variant.to_ascii_uppercase(),
            Self::CamelCase => variant[..1].to_ascii_lowercase() + &variant[1..],
            Self::SnakeCase => {
                let mut snake = String::new();
                for (i, ch) in variant.char_indices() {
                    if i > 0 && ch.is_uppercase() {
                        snake.push('_');
                    }
                    snake.push(ch.to_ascii_lowercase());
                }
                snake
            }
            Self::ScreamingSnakeCase => Self::SnakeCase
                .apply_to_variant(variant)
                .to_ascii_uppercase(),
            Self::KebabCase => Self::SnakeCase.apply_to_variant(variant).replace('_', "-"),
            Self::ScreamingKebabCase => Self::ScreamingSnakeCase
                .apply_to_variant(variant)
                .replace('_', "-"),
        }
    }

    /// Apply a renaming rule to a struct field, returning the version expected in the source.
    pub fn apply_to_field(&self, field: &str) -> String {
        match *self {
            Self::LowerCase | Self::SnakeCase => field.into(),
            Self::UpperCase => field.to_ascii_uppercase(),
            Self::PascalCase => {
                let mut pascal = String::new();
                let mut capitalize = true;
                for ch in field.chars() {
                    if ch == '_' {
                        capitalize = true;
                    } else if capitalize {
                        pascal.push(ch.to_ascii_uppercase());
                        capitalize = false;
                    } else {
                        pascal.push(ch);
                    }
                }
                pascal
            }
            Self::CamelCase => {
                let pascal = Self::PascalCase.apply_to_field(field);
                pascal[..1].to_ascii_lowercase() + &pascal[1..]
            }
            Self::ScreamingSnakeCase => field.to_ascii_uppercase(),
            Self::KebabCase => field.replace('_', "-"),
            Self::ScreamingKebabCase => Self::ScreamingSnakeCase
                .apply_to_field(field)
                .replace('_', "-"),
        }
    }
}

impl core::str::FromStr for RenameRule {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_rename_all_str(s)
    }
}
impl core::convert::TryFrom<&str> for RenameRule {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
impl core::fmt::Display for RenameRule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_rename_all_str())
    }
}

//
#[derive(Debug)]
pub enum ParseError {
    Unknown(String),
}

impl ParseError {
    pub fn msg_for_rename_all(&self) -> String {
        match self {
            Self::Unknown(s) => format!(
                r#"unknown rename rule `rename_all = "{}"`, expected one of {}"#,
                s,
                RENAME_RULES
                    .iter()
                    .map(|(name, _)| format!(r#""{name}""#))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::string::ToString as _;
    use core::str::FromStr as _;

    use RenameRule::*;

    #[test]
    fn test_from_rename_all_str_and_to_rename_all_str() {
        for (name, rule) in RENAME_RULES {
            assert_eq!(&RenameRule::from_rename_all_str(name).unwrap(), rule);
            assert_eq!(&rule.to_rename_all_str(), name);
        }

        match RenameRule::from_rename_all_str("foo") {
            Ok(_) => panic!(""),
            Err(ParseError::Unknown(s)) => assert_eq!(s, "foo"),
        }
    }

    #[test]
    fn test_impl_trait() {
        let (name, rule) = RENAME_RULES.first().unwrap();
        assert_eq!(RenameRule::from_str(name).unwrap(), *rule);
        assert_eq!(name.parse::<RenameRule>().unwrap(), *rule);
        assert_eq!(RenameRule::try_from(*name).unwrap(), *rule);
        assert_eq!(rule.to_string(), *name);
    }

    #[test]
    fn test_parse_error_msg() {
        match RenameRule::from_rename_all_str("foo") {
            Ok(_) => panic!(""),
            Err(err) => assert_eq!(
                err.msg_for_rename_all(),
                r#"unknown rename rule `rename_all = "foo"`, expected one of "lowercase", "UPPERCASE", "PascalCase", "camelCase", "snake_case", "SCREAMING_SNAKE_CASE", "kebab-case", "SCREAMING-KEBAB-CASE""#
            ),
        }
    }

    #[test]
    fn rename_variants() {
        for &(original, lower, upper, camel, snake, screaming, kebab, screaming_kebab) in &[
            (
                "Outcome", "outcome", "OUTCOME", "outcome", "outcome", "OUTCOME", "outcome",
                "OUTCOME",
            ),
            (
                "VeryTasty",
                "verytasty",
                "VERYTASTY",
                "veryTasty",
                "very_tasty",
                "VERY_TASTY",
                "very-tasty",
                "VERY-TASTY",
            ),
            ("A", "a", "A", "a", "a", "A", "a", "A"),
            ("Z42", "z42", "Z42", "z42", "z42", "Z42", "z42", "Z42"),
        ] {
            assert_eq!(LowerCase.apply_to_variant(original), lower);
            assert_eq!(UpperCase.apply_to_variant(original), upper);
            assert_eq!(PascalCase.apply_to_variant(original), original);
            assert_eq!(CamelCase.apply_to_variant(original), camel);
            assert_eq!(SnakeCase.apply_to_variant(original), snake);
            assert_eq!(ScreamingSnakeCase.apply_to_variant(original), screaming);
            assert_eq!(KebabCase.apply_to_variant(original), kebab);
            assert_eq!(
                ScreamingKebabCase.apply_to_variant(original),
                screaming_kebab
            );
        }
    }

    #[test]
    fn rename_fields() {
        for &(original, upper, pascal, camel, screaming, kebab, screaming_kebab) in &[
            (
                "outcome", "OUTCOME", "Outcome", "outcome", "OUTCOME", "outcome", "OUTCOME",
            ),
            (
                "very_tasty",
                "VERY_TASTY",
                "VeryTasty",
                "veryTasty",
                "VERY_TASTY",
                "very-tasty",
                "VERY-TASTY",
            ),
            ("a", "A", "A", "a", "A", "a", "A"),
            ("z42", "Z42", "Z42", "z42", "Z42", "z42", "Z42"),
        ] {
            assert_eq!(UpperCase.apply_to_field(original), upper);
            assert_eq!(PascalCase.apply_to_field(original), pascal);
            assert_eq!(CamelCase.apply_to_field(original), camel);
            assert_eq!(SnakeCase.apply_to_field(original), original);
            assert_eq!(ScreamingSnakeCase.apply_to_field(original), screaming);
            assert_eq!(KebabCase.apply_to_field(original), kebab);
            assert_eq!(ScreamingKebabCase.apply_to_field(original), screaming_kebab);
        }
    }
}
