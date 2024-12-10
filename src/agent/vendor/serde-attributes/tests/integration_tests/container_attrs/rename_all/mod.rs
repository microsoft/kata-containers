mod examples;

//
//
//
use std::convert::TryFrom as _;

use serde_attributes::{
    rename_all::serde_rename_rule::RenameRule, RenameAll, RenameAllIndependent,
};

use super::{parse_darling_rename_all, parse_serde_meta};

#[test]
fn simple() {
    let lines: Vec<_> = include_str!("examples.rs").lines().collect();

    let input = lines[0..=2].join("\r\n");
    assert_eq!(
        RenameAll::try_from(&parse_serde_meta(&input)).unwrap(),
        RenameAll::Normal(RenameRule::SnakeCase)
    );
    assert_eq!(
        parse_darling_rename_all(&input).unwrap(),
        RenameAll::Normal(RenameRule::SnakeCase)
    );

    let input = lines[4..=6].join("\r\n");
    assert_eq!(
        RenameAll::try_from(&parse_serde_meta(&input)).unwrap(),
        RenameAll::Independent(RenameAllIndependent::Serialize(RenameRule::LowerCase))
    );
    assert_eq!(
        parse_darling_rename_all(&input).unwrap(),
        RenameAll::Independent(RenameAllIndependent::Serialize(RenameRule::LowerCase))
    );

    let input = lines[8..=10].join("\r\n");
    assert_eq!(
        RenameAll::try_from(&parse_serde_meta(&input)).unwrap(),
        RenameAll::Independent(RenameAllIndependent::Deserialize(RenameRule::UpperCase))
    );
    assert_eq!(
        parse_darling_rename_all(&input).unwrap(),
        RenameAll::Independent(RenameAllIndependent::Deserialize(RenameRule::UpperCase))
    );

    let input = lines[12..=14].join("\r\n");
    assert_eq!(
        RenameAll::try_from(&parse_serde_meta(&input)).unwrap(),
        RenameAll::Independent(RenameAllIndependent::Both {
            serialize: RenameRule::LowerCase,
            deserialize: RenameRule::UpperCase
        })
    );
    assert_eq!(
        parse_darling_rename_all(&input).unwrap(),
        RenameAll::Independent(RenameAllIndependent::Both {
            serialize: RenameRule::LowerCase,
            deserialize: RenameRule::UpperCase
        })
    );
}
