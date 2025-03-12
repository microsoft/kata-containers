use darling::{
    ast::Data as DarlingData, util::Ignored, Error as DarlingError, FromDeriveInput, FromVariant,
};
use serde_attributes::Alias;
use syn::{parse_str, Data, DataEnum, DeriveInput, Meta, MetaList, NestedMeta};

#[allow(dead_code)]
pub fn parse_serde_meta(input: &str) -> Meta {
    parse_serde_meta_list(input).first().cloned().unwrap()
}

pub fn parse_serde_meta_list(input: &str) -> Vec<Meta> {
    let derive_input = parse_str::<DeriveInput>(input).unwrap();
    let attrs = &derive_input.attrs;
    match attrs[0].parse_meta().unwrap() {
        Meta::List(MetaList {
            path,
            paren_token: _,
            nested: _,
        }) if path.is_ident("derive") => {}
        meta => {
            println!("{meta:?}");
            panic!()
        }
    }
    match derive_input.data {
        Data::Enum(DataEnum {
            enum_token: _,
            brace_token: _,
            variants,
        }) => {
            let attrs = &variants[0].attrs;
            attrs
                .iter()
                .map(|attr| match attr.parse_meta().unwrap() {
                    Meta::List(MetaList {
                        path,
                        paren_token: _,
                        nested,
                    }) if path.is_ident("serde") => match nested.first().cloned() {
                        Some(NestedMeta::Meta(meta)) => meta,
                        _ => panic!(),
                    },
                    meta => {
                        println!("{meta:?}");
                        panic!()
                    }
                })
                .collect()
        }
        data => {
            println!("{data:?}");
            panic!()
        }
    }
}

pub fn parse_darling_alias(input: &str) -> Result<Vec<Alias>, DarlingError> {
    #[derive(FromDeriveInput)]
    #[darling(attributes(serde))]
    struct SerdeDerive {
        data: DarlingData<SerdeVariant, Ignored>,
    }

    #[derive(FromVariant, Debug, Clone)]
    #[darling(attributes(serde))]
    struct SerdeVariant {
        #[darling(default, multiple, rename = "alias")]
        alias_vec: Vec<Alias>,
    }

    let derive = SerdeDerive::from_derive_input(
        &parse_str(
            input
                .replace(
                    r#"#[derive(serde::Serialize, serde::Deserialize)]"#,
                    r#"#[derive(SerdeDerive)]"#,
                )
                .as_str(),
        )
        .unwrap(),
    )?;

    let variants = match &derive.data {
        DarlingData::Enum(variants) => variants,
        _ => {
            println!("{:?}", derive.data);
            panic!()
        }
    };

    Ok(variants[0].to_owned().alias_vec)
}
