use serde_rename_rule::{ParseError as RenameRuleParseError, RenameRule};
use syn::{Lit, Meta, MetaNameValue, NestedMeta};

use crate::rename::{syn::FromMetaError as RenameFromMetaError, Rename, RenameIndependent};

use super::{RenameAll, RenameAllIndependent};

/// [Ref](https://github.com/serde-rs/serde/blob/v1.0.127/serde_derive/src/internals/symbol.rs#L24)
pub const RENAME_ALL: &str = "rename_all";

/// [Ref](https://github.com/serde-rs/serde/blob/v1.0.127/serde_derive/src/internals/attr.rs#L335-L364)
impl<'a> core::convert::TryFrom<&'a Meta> for RenameAll {
    type Error = FromMetaError<'a>;

    fn try_from(meta: &'a Meta) -> Result<Self, Self::Error> {
        match Rename::try_from_meta(meta, RENAME_ALL) {
            Ok(rename) => match rename {
                Rename::Normal(name) => RenameRule::from_rename_all_str(name.as_str())
                    .map(Self::Normal)
                    .map_err(FromMetaError::RenameRuleParseError),
                Rename::Independent(RenameIndependent::Serialize(ser_name)) => {
                    RenameRule::from_rename_all_str(ser_name.as_str())
                        .map(|x| Self::Independent(RenameAllIndependent::Serialize(x)))
                        .map_err(FromMetaError::RenameRuleParseError)
                }
                Rename::Independent(RenameIndependent::Deserialize(de_name)) => {
                    RenameRule::from_rename_all_str(de_name.as_str())
                        .map(|x| Self::Independent(RenameAllIndependent::Deserialize(x)))
                        .map_err(FromMetaError::RenameRuleParseError)
                }
                Rename::Independent(RenameIndependent::Both {
                    serialize: ser_name,
                    deserialize: de_name,
                }) => Ok(Self::Independent(RenameAllIndependent::Both {
                    serialize: RenameRule::from_rename_all_str(ser_name.as_str())
                        .map_err(FromMetaError::RenameRuleParseError)?,
                    deserialize: RenameRule::from_rename_all_str(de_name.as_str())
                        .map_err(FromMetaError::RenameRuleParseError)?,
                })),
            },
            Err(err) => match err {
                RenameFromMetaError::MetaTypeOrPathMismatch(meta) => {
                    Err(FromMetaError::MetaTypeOrPathMismatch(meta))
                }
                RenameFromMetaError::LitTypeMismatch(lit) => {
                    Err(FromMetaError::LitTypeMismatch(lit))
                }
                RenameFromMetaError::NestedMetaTypeMismatch(nested_meta) => {
                    Err(FromMetaError::NestedMetaTypeMismatch(nested_meta))
                }
                RenameFromMetaError::NestedMetaPathMismatch(nested_meta, meta_name_value) => Err(
                    FromMetaError::NestedMetaPathMismatch(nested_meta, meta_name_value),
                ),
                RenameFromMetaError::AtLeastOneOfSerAndDe => {
                    Err(FromMetaError::AtLeastOneOfSerAndDe)
                }
            },
        }
    }
}

pub enum FromMetaError<'a> {
    MetaTypeOrPathMismatch(&'a Meta),
    LitTypeMismatch(&'a Lit),
    NestedMetaTypeMismatch(&'a NestedMeta),
    NestedMetaPathMismatch(&'a NestedMeta, &'a MetaNameValue),
    AtLeastOneOfSerAndDe,
    RenameRuleParseError(RenameRuleParseError),
}
impl<'a> core::fmt::Debug for FromMetaError<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MetaTypeOrPathMismatch(_) => write!(f, "MetaTypeOrPathMismatch"),
            Self::LitTypeMismatch(_) => write!(f, "LitTypeMismatch"),
            Self::NestedMetaTypeMismatch(_) => write!(f, "NestedMetaTypeMismatch"),
            Self::NestedMetaPathMismatch(_, _) => write!(f, "NestedMetaPathMismatch"),
            Self::AtLeastOneOfSerAndDe => write!(f, "AtLeastOneOfSerAndDe"),
            Self::RenameRuleParseError(_) => write!(f, "RenameRuleParseError"),
        }
    }
}
impl<'a> core::fmt::Display for FromMetaError<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
#[cfg(feature = "std")]
impl<'a> std::error::Error for FromMetaError<'a> {}
