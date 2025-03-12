use darling::{Error as DarlingError, FromDeriveInput};
use serde_attributes::{Rename, RenameAll};
use syn::{parse_str, DeriveInput, Meta, MetaList, NestedMeta};

pub fn parse_serde_meta(input: &str) -> Meta {
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
    match attrs[1].parse_meta().unwrap() {
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
    }
}

pub fn parse_darling_rename(input: &str) -> Result<Rename, DarlingError> {
    #[derive(FromDeriveInput)]
    #[darling(attributes(serde))]
    struct SerdeDerive {
        rename: Rename,
    }

    SerdeDerive::from_derive_input(
        &parse_str(
            input
                .replace(
                    r#"#[derive(serde::Serialize, serde::Deserialize)]"#,
                    r#"#[derive(SerdeDerive)]"#,
                )
                .as_str(),
        )
        .unwrap(),
    )
    .map(|x| x.rename)
}

pub fn parse_darling_rename_all(input: &str) -> Result<RenameAll, DarlingError> {
    #[derive(FromDeriveInput)]
    #[darling(attributes(serde))]
    struct SerdeDerive {
        rename_all: RenameAll,
    }

    SerdeDerive::from_derive_input(
        &parse_str(
            input
                .replace(
                    r#"#[derive(serde::Serialize, serde::Deserialize)]"#,
                    r#"#[derive(SerdeDerive)]"#,
                )
                .as_str(),
        )
        .unwrap(),
    )
    .map(|x| x.rename_all)
}
