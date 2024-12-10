use core::convert::TryFrom as _;

use darling_core::{Error as DarlingError, FromMeta};
use syn::Meta;

use super::{syn::FromMetaError, Alias};

impl FromMeta for Alias {
    fn from_meta(meta: &Meta) -> Result<Self, DarlingError> {
        Self::try_from(meta).map_err(|err| match err {
            FromMetaError::MetaTypeOrPathMismatch(meta) => match meta {
                Meta::Path(_) => DarlingError::unexpected_type("Meta::Path"),
                Meta::List(_) => DarlingError::unexpected_type("Meta::List"),
                Meta::NameValue(meta_name_value) => {
                    DarlingError::unknown_field_path(&meta_name_value.path)
                }
            },
            FromMetaError::LitTypeMismatch(lit) => DarlingError::unexpected_lit_type(lit),
        })
    }
}
