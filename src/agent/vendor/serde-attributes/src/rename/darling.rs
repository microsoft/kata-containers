use core::convert::TryFrom as _;

use darling_core::{Error as DarlingError, FromMeta};
use syn::Meta;

use super::{syn::FromMetaError, Rename};

impl FromMeta for Rename {
    fn from_meta(meta: &Meta) -> Result<Self, DarlingError> {
        Self::try_from(meta).map_err(|err| match err {
            FromMetaError::MetaTypeOrPathMismatch(meta) => match meta {
                Meta::Path(_) => DarlingError::unexpected_type("Meta::Path"),
                Meta::List(meta_list) => DarlingError::unknown_field_path(&meta_list.path),
                Meta::NameValue(meta_name_value) => {
                    DarlingError::unknown_field_path(&meta_name_value.path)
                }
            },
            FromMetaError::LitTypeMismatch(lit) => DarlingError::unexpected_lit_type(lit),
            FromMetaError::NestedMetaTypeMismatch(_) => {
                DarlingError::unexpected_type("NestedMeta::Meta(!Meta::NameValue)")
            }
            FromMetaError::NestedMetaPathMismatch(_, meta_name_value) => {
                DarlingError::unknown_field_path(&meta_name_value.path)
            }
            FromMetaError::AtLeastOneOfSerAndDe => {
                DarlingError::custom("must be at least one the serialize and deserialize")
            }
        })
    }
}
