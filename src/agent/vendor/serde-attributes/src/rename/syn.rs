use syn::{Lit, Meta, MetaNameValue, NestedMeta};

use crate::{DESERIALIZE, SERIALIZE};

use super::{Rename, RenameIndependent};

/// [Ref](https://github.com/serde-rs/serde/blob/v1.0.127/serde_derive/src/internals/symbol.rs#L23)
pub const RENAME: &str = "rename";

impl Rename {
    /// [Ref](https://github.com/serde-rs/serde/blob/v1.0.127/serde_derive/src/internals/attr.rs#L319-L333)
    pub fn try_from_meta<'a>(meta: &'a Meta, path_name: &str) -> Result<Self, FromMetaError<'a>> {
        match meta {
            Meta::NameValue(ref meta_name_value) if meta_name_value.path.is_ident(path_name) => {
                match &meta_name_value.lit {
                    Lit::Str(ref s) => Ok(Self::Normal(s.value())),
                    lit => Err(FromMetaError::LitTypeMismatch(lit)),
                }
            }
            Meta::List(ref meta_list) if meta_list.path.is_ident(path_name) => {
                let mut ser_name = None;
                let mut de_name = None;

                for nested_meta in &meta_list.nested {
                    match nested_meta {
                        NestedMeta::Meta(Meta::NameValue(meta_name_value)) => {
                            if meta_name_value.path.is_ident(SERIALIZE) {
                                match &meta_name_value.lit {
                                    Lit::Str(ref s) => ser_name = Some(s.value()),
                                    _ => {
                                        return Err(FromMetaError::LitTypeMismatch(
                                            &meta_name_value.lit,
                                        ))
                                    }
                                }
                            } else if meta_name_value.path.is_ident(DESERIALIZE) {
                                match &meta_name_value.lit {
                                    Lit::Str(ref s) => de_name = Some(s.value()),
                                    _ => {
                                        return Err(FromMetaError::LitTypeMismatch(
                                            &meta_name_value.lit,
                                        ))
                                    }
                                }
                            } else {
                                return Err(FromMetaError::NestedMetaPathMismatch(
                                    nested_meta,
                                    meta_name_value,
                                ));
                            }
                        }
                        nested_meta => {
                            return Err(FromMetaError::NestedMetaTypeMismatch(nested_meta))
                        }
                    }
                }
                match (ser_name, de_name) {
                    (None, None) => Err(FromMetaError::AtLeastOneOfSerAndDe),
                    (None, Some(de_name)) => {
                        Ok(Self::Independent(RenameIndependent::Deserialize(de_name)))
                    }
                    (Some(ser_name), None) => {
                        Ok(Self::Independent(RenameIndependent::Serialize(ser_name)))
                    }
                    (Some(ser_name), Some(de_name)) => {
                        Ok(Self::Independent(RenameIndependent::Both {
                            serialize: ser_name,
                            deserialize: de_name,
                        }))
                    }
                }
            }
            meta => Err(FromMetaError::MetaTypeOrPathMismatch(meta)),
        }
    }
}

/// [Ref](https://github.com/serde-rs/serde/blob/v1.0.127/serde_derive/src/internals/attr.rs#L319-L333)
impl<'a> core::convert::TryFrom<&'a Meta> for Rename {
    type Error = FromMetaError<'a>;

    fn try_from(meta: &'a Meta) -> Result<Self, Self::Error> {
        Self::try_from_meta(meta, RENAME)
    }
}

pub enum FromMetaError<'a> {
    MetaTypeOrPathMismatch(&'a Meta),
    LitTypeMismatch(&'a Lit),
    NestedMetaTypeMismatch(&'a NestedMeta),
    NestedMetaPathMismatch(&'a NestedMeta, &'a MetaNameValue),
    AtLeastOneOfSerAndDe,
}
impl<'a> core::fmt::Debug for FromMetaError<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MetaTypeOrPathMismatch(_) => write!(f, "MetaTypeOrPathMismatch"),
            Self::LitTypeMismatch(_) => write!(f, "LitTypeMismatch"),
            Self::NestedMetaTypeMismatch(_) => write!(f, "NestedMetaTypeMismatch"),
            Self::NestedMetaPathMismatch(_, _) => write!(f, "NestedMetaPathMismatch"),
            Self::AtLeastOneOfSerAndDe => write!(f, "AtLeastOneOfSerAndDe"),
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
