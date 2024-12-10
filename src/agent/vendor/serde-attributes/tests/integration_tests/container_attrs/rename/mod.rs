mod examples;

//
//
//
use std::convert::TryFrom as _;

use serde_attributes::{Rename, RenameIndependent};

use super::{parse_darling_rename, parse_serde_meta};

#[test]
fn simple() {
    let lines: Vec<_> = include_str!("examples.rs").lines().collect();

    let input = lines[0..=2].join("\r\n");
    assert_eq!(
        Rename::try_from(&parse_serde_meta(&input)).unwrap(),
        Rename::Normal("name".to_owned())
    );
    assert_eq!(
        parse_darling_rename(&input).unwrap(),
        Rename::Normal("name".to_owned())
    );

    let input = lines[4..=6].join("\r\n");
    assert_eq!(
        Rename::try_from(&parse_serde_meta(&input)).unwrap(),
        Rename::Independent(RenameIndependent::Serialize("ser_name".to_owned()))
    );
    assert_eq!(
        parse_darling_rename(&input).unwrap(),
        Rename::Independent(RenameIndependent::Serialize("ser_name".to_owned()))
    );

    let input = lines[8..=10].join("\r\n");
    assert_eq!(
        Rename::try_from(&parse_serde_meta(&input)).unwrap(),
        Rename::Independent(RenameIndependent::Deserialize("de_name".to_owned()))
    );
    assert_eq!(
        parse_darling_rename(&input).unwrap(),
        Rename::Independent(RenameIndependent::Deserialize("de_name".to_owned()))
    );

    let input = lines[12..=14].join("\r\n");
    assert_eq!(
        Rename::try_from(&parse_serde_meta(&input)).unwrap(),
        Rename::Independent(RenameIndependent::Both {
            serialize: "ser_name".to_owned(),
            deserialize: "de_name".to_owned()
        })
    );
    assert_eq!(
        parse_darling_rename(&input).unwrap(),
        Rename::Independent(RenameIndependent::Both {
            serialize: "ser_name".to_owned(),
            deserialize: "de_name".to_owned()
        })
    );
}
