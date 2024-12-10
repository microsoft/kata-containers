use alloc::{borrow::ToOwned as _, format, string::String, vec, vec::Vec};

use darling::{
    ast::{Data, Fields},
    util::Ignored,
    FromDeriveInput, FromVariant,
};
use proc_macro2::Span;
use serde_attributes::{Alias, Rename, RenameAll};
use syn::{
    parse::{Parse, ParseStream},
    Attribute, DeriveInput, Error as SynError, Expr, Generics, Ident, Type, Visibility,
};

//
pub struct Input {
    pub ident: Ident,
    pub rename_all: Option<RenameAll>,
    pub crate_str: Option<String>,
    pub serde_expr: Expr,
    pub variants: Vec<Variant>,
    pub default_variant: Option<DefaultVariant>,
}

pub struct Variant {
    pub ident: Ident,
    pub rename: Option<Rename>,
    pub alias_vec: Option<Vec<Alias>>,
    pub skip_serializing: Option<bool>,
    pub skip_deserializing: Option<bool>,
}

#[derive(Clone)]
pub struct DefaultVariant {
    pub ident: Ident,
    pub r#type: Option<Type>,
}

impl Parse for Input {
    fn parse(input: ParseStream) -> Result<Self, SynError> {
        let call_site = Span::call_site();

        let derive_input = DeriveInput::parse(input)?;
        let enum_derive_input = EnumDeriveInput::from_derive_input(&derive_input)
            .map_err(|err| SynError::new(call_site, err.write_errors()))?;
        let enum_variants = match &enum_derive_input.data {
            Data::Enum(enum_variants) => enum_variants,
            _ => return Err(SynError::new(call_site, "input must be an enum")),
        };

        let ident = enum_derive_input.ident;
        let rename_all = enum_derive_input.rename_all;
        let crate_str = enum_derive_input.crate_;
        let serde_expr = if let Some(crate_str) = &crate_str {
            syn::parse_str::<Expr>(crate_str).map_err(|_| {
                SynError::new(call_site, r#"#[serde(crate = "...")] must be an Expr"#)
            })?
        } else {
            syn::parse_str::<Expr>("serde").expect("")
        };

        let mut variants = vec![];
        let mut default_variant = None;

        let mut enum_variants_iter = enum_variants.iter().rev();
        let enum_variant = enum_variants_iter
            .next()
            .ok_or_else(|| SynError::new(call_site, "there must be at least one variant"))?;
        if enum_variant.is_other {
            default_variant = Some(parse_default_variant(enum_variant)?);
        } else {
            variants.push(parse_variant(enum_variant)?)
        }
        for enum_variant in enum_variants_iter.rev() {
            if enum_variant.is_other {
                if default_variant.is_some() {
                    return Err(SynError::new(
                        call_site,
                        "only one variant can be #[serde(other)]",
                    ));
                } else {
                    return Err(SynError::new(
                        call_site,
                        "the #[serde(other)] variant should be at the end",
                    ));
                }
            } else {
                variants.push(parse_variant(enum_variant)?)
            }
        }

        let generics = enum_derive_input.generics;
        if !generics.params.is_empty() || generics.where_clause.is_some() {
            return Err(SynError::new(call_site, "generic enum is not supported"));
        }

        Ok(Self {
            ident,
            rename_all,
            crate_str,
            serde_expr,
            variants,
            default_variant,
        })
    }
}

fn parse_variant(enum_variant: &EnumVariant) -> Result<Variant, SynError> {
    if !enum_variant.fields.is_unit() {
        return Err(SynError::new(
            enum_variant.ident.span(),
            "must be a unit variant",
        ));
    }

    Ok(Variant {
        ident: enum_variant.ident.to_owned(),
        rename: enum_variant.rename.to_owned(),
        alias_vec: if enum_variant.alias_vec.is_empty() {
            None
        } else {
            Some(enum_variant.alias_vec.to_owned())
        },
        skip_serializing: enum_variant.skip_serializing.or(enum_variant.skip),
        skip_deserializing: enum_variant.skip_deserializing.or(enum_variant.skip),
    })
}

fn parse_default_variant(enum_variant: &EnumVariant) -> Result<DefaultVariant, SynError> {
    if enum_variant.fields.is_tuple() {
        let mut types_iter = enum_variant.fields.iter().cloned();
        let r#type = types_iter
            .next()
            .ok_or_else(|| SynError::new(enum_variant.ident.span(), "must be at least one type"))?;
        if types_iter.next().is_some() {
            return Err(SynError::new(enum_variant.ident.span(), "must be one type"));
        }

        Ok(DefaultVariant {
            ident: enum_variant.ident.to_owned(),
            r#type: Some(r#type),
        })
    } else if enum_variant.fields.is_unit() {
        Ok(DefaultVariant {
            ident: enum_variant.ident.to_owned(),
            r#type: None,
        })
    } else {
        Err(SynError::new(
            enum_variant.ident.span(),
            "must be a tuple or unit variant",
        ))
    }
}

#[derive(FromDeriveInput, Debug)]
#[darling(attributes(serde), forward_attrs(doc))]
struct EnumDeriveInput {
    #[allow(dead_code)]
    attrs: Vec<Attribute>,
    #[allow(dead_code)]
    vis: Visibility,
    ident: Ident,
    generics: Generics,
    data: Data<EnumVariant, Ignored>,

    #[darling(default)]
    rename_all: Option<RenameAll>,
    #[darling(default, rename = "crate")]
    crate_: Option<String>,
}

#[derive(FromVariant, Debug)]
#[darling(attributes(serde), forward_attrs(doc))]
struct EnumVariant {
    #[allow(dead_code)]
    attrs: Vec<Attribute>,
    ident: Ident,
    fields: Fields<Type>,
    #[allow(dead_code)]
    discriminant: Option<Expr>,

    #[darling(default)]
    rename: Option<Rename>,
    #[darling(default, multiple, rename = "alias")]
    alias_vec: Vec<Alias>,
    #[darling(default)]
    skip: Option<bool>,
    #[darling(default)]
    skip_serializing: Option<bool>,
    #[darling(default)]
    skip_deserializing: Option<bool>,
    #[darling(default, rename = "other", map = "Self::make_is_other")]
    is_other: bool,
}
impl EnumVariant {
    fn make_is_other(v: Option<()>) -> bool {
        v.is_some()
    }
}
