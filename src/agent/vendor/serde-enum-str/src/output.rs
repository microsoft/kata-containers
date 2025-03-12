use alloc::vec::Vec;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens, TokenStreamExt as _};
use syn::Ident;

use super::input::Input;

//
pub struct SerdeEnum<'a> {
    input: &'a Input,
    category: SerdeEnumCategory,
}
pub enum SerdeEnumCategory {
    Ser,
    De,
}
impl<'a> SerdeEnum<'a> {
    pub fn new(input: &'a Input, category: SerdeEnumCategory) -> Self {
        Self { input, category }
    }
    pub fn ident(&self) -> Ident {
        format_ident!("__{}{}", self.input.ident, self.suffix())
    }
    fn suffix(&self) -> &'static str {
        match self.category {
            SerdeEnumCategory::Ser => "Ser",
            SerdeEnumCategory::De => "De",
        }
    }
}
impl<'a> ToTokens for SerdeEnum<'a> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let input = self.input;
        let serde_expr = &input.serde_expr;

        let derive_serde = match self.category {
            SerdeEnumCategory::Ser => {
                quote!(#[derive(#serde_expr::Serialize)])
            }
            SerdeEnumCategory::De => {
                quote!(#[derive(#serde_expr::Deserialize)])
            }
        };
        let serde_rename_all = if let Some(rename_all) = &input.rename_all {
            match self.category {
                SerdeEnumCategory::Ser => {
                    if let Some(serialize) = &rename_all.ser_rule() {
                        let s = serialize.to_rename_all_str();
                        quote!(#[serde(rename_all(serialize = #s))])
                    } else {
                        quote!()
                    }
                }
                SerdeEnumCategory::De => {
                    if let Some(deserialize) = &rename_all.de_rule() {
                        let s = deserialize.to_rename_all_str();
                        quote!(#[serde(rename_all(deserialize = #s))])
                    } else {
                        quote!()
                    }
                }
            }
        } else {
            quote!()
        };
        let serde_crate = if let Some(crate_str) = &input.crate_str {
            quote!(#[serde(crate = #crate_str)])
        } else {
            quote!()
        };
        let ident = self.ident();
        let variants = &input
            .variants
            .iter()
            .map(|variant| {
                let ident = &variant.ident;
                let serde_rename = if let Some(rename) = &variant.rename {
                    match self.category {
                        SerdeEnumCategory::Ser => {
                            if let Some(serialize) = &rename.ser_name() {
                                quote!(#[serde(rename(serialize = #serialize))])
                            } else {
                                quote!()
                            }
                        }
                        SerdeEnumCategory::De => {
                            if let Some(deserialize) = &rename.de_name() {
                                quote!(#[serde(rename(deserialize = #deserialize))])
                            } else {
                                quote!()
                            }
                        }
                    }
                } else {
                    quote!()
                };
                let serde_alias = match self.category {
                    SerdeEnumCategory::Ser => quote!(),
                    SerdeEnumCategory::De => {
                        if let Some(alias_vec) = &variant.alias_vec {
                            let tokens = alias_vec
                                .iter()
                                .map(|alias| {
                                    let alias = &alias.0;
                                    quote!(#[serde(alias = #alias)])
                                })
                                .collect::<Vec<_>>();
                            quote! {
                                #(#tokens)*
                            }
                        } else {
                            quote!()
                        }
                    }
                };
                let serde_skip = match self.category {
                    SerdeEnumCategory::Ser => {
                        if variant.skip_serializing == Some(true) {
                            quote!(#[serde(skip_serializing)])
                        } else {
                            quote!()
                        }
                    }
                    SerdeEnumCategory::De => {
                        if variant.skip_deserializing == Some(true) {
                            quote!(#[serde(skip_deserializing)])
                        } else {
                            quote!()
                        }
                    }
                };
                quote! {
                    #serde_rename
                    #serde_alias
                    #serde_skip
                    #[allow(non_camel_case_types, clippy::all)]
                    #ident,
                }
            })
            .collect::<Vec<_>>();

        let token = quote! {
            #derive_serde
            #serde_rename_all
            #serde_crate
            #[allow(dead_code, clippy::all)]
            enum #ident {
                #(#variants)*
            }
        };
        tokens.append_all(token);
    }
}
