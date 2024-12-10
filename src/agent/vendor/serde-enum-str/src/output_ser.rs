use alloc::{string::ToString as _, vec::Vec};

use proc_macro2::TokenStream;
use quote::{quote, ToTokens, TokenStreamExt as _};

use super::{
    input::Input,
    output::{SerdeEnum, SerdeEnumCategory},
};

//
pub struct InputWrapper(pub Input);

impl ToTokens for InputWrapper {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let input = &self.0;
        let serde_expr = &input.serde_expr;

        let ser_enum = SerdeEnum::new(input, SerdeEnumCategory::Ser);
        let ser_enum_ident = ser_enum.ident();

        let token = quote! {
            #ser_enum
        };
        tokens.append_all(token);

        //
        let impl_ident = &input.ident;

        //
        let impl_serialize_variants = &input
            .variants
            .iter()
            .map(|variant| {
                let ident = &variant.ident;
                quote! {
                    Self::#ident => #ser_enum_ident::#ident,
                }
            })
            .collect::<Vec<_>>();
        let impl_serialize_default_variant = if let Some(default_variant) = &input.default_variant {
            let ident = &default_variant.ident;
            if default_variant.r#type.is_some() {
                quote! {
                    Self::#ident(ref s) => return #serde_expr::Serialize::serialize(s, serializer),
                }
            } else {
                let mut name = ident.to_string();
                if let Some(rename_all) = &input.rename_all {
                    if let Some(rename_rule) = &rename_all.ser_rule() {
                        name = rename_rule.apply_to_variant(&name);
                    }
                }
                quote! {
                    Self::#ident => return #serde_expr::Serialize::serialize(#name, serializer),
                }
            }
        } else {
            quote!()
        };

        let token = quote! {
            impl #serde_expr::Serialize for #impl_ident {
                fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
                where
                    S: #serde_expr::Serializer,
                {
                    let value = match *self {
                        #(#impl_serialize_variants)*
                        #impl_serialize_default_variant
                    };
                    #serde_expr::Serialize::serialize(&value, serializer)
                }
            }
        };
        tokens.append_all(token);

        //
        let impl_display_variants = &input
            .variants
            .iter()
            .map(|variant| {
                let ident = &variant.ident;
                if variant.skip_serializing == Some(true) {
                    let mut name = ident.to_string();
                    if let Some(rename_all) = &input.rename_all {
                        if let Some(rename_rule) = &rename_all.ser_rule() {
                            name = rename_rule.apply_to_variant(&name);
                        }
                    }
                    quote! {
                        Self::#ident => write!(f, "{}", #name),
                    }
                } else {
                    quote! {
                        Self::#ident => self.serialize(f),
                    }
                }
            })
            .collect::<Vec<_>>();
        let impl_display_default_variant = if let Some(default_variant) = &input.default_variant {
            let ident = &default_variant.ident;
            if default_variant.r#type.is_some() {
                quote! {
                    Self::#ident(ref s) => write!(f, "{}", s),
                }
            } else {
                let mut name = ident.to_string();
                if let Some(rename_all) = &input.rename_all {
                    if let Some(rename_rule) = &rename_all.ser_rule() {
                        name = rename_rule.apply_to_variant(&name);
                    }
                }
                quote! {
                    Self::#ident => write!(f, "{}", #name),
                }
            }
        } else {
            quote!()
        };

        let token = quote! {
            // https://docs.serde.rs/serde/trait.Serializer.html#foreign-impls
            impl ::core::fmt::Display for #impl_ident {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    use #serde_expr::Serialize as _;

                    match *self {
                        #(#impl_display_variants)*
                        #impl_display_default_variant
                    }
                }
            }
        };
        tokens.append_all(token);
    }
}
