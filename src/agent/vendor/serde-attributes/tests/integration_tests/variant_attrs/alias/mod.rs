mod examples;

//
//
//
use std::convert::TryFrom as _;

use serde_attributes::Alias;

use super::{parse_darling_alias, parse_serde_meta_list};

#[test]
fn simple() {
    let lines: Vec<_> = include_str!("examples.rs").lines().collect();

    let input = lines[0..=4].join("\r\n");
    assert_eq!(
        parse_serde_meta_list(&input)
            .iter()
            .map(|x| Alias::try_from(x).unwrap())
            .collect::<Vec<_>>(),
        vec![Alias("name".to_owned())]
    );
    assert_eq!(
        parse_darling_alias(&input).unwrap(),
        vec![Alias("name".to_owned())]
    );

    let input = lines[6..=11].join("\r\n");
    assert_eq!(
        parse_serde_meta_list(&input)
            .iter()
            .map(|x| Alias::try_from(x).unwrap())
            .collect::<Vec<_>>(),
        vec![Alias("name_a".to_owned()), Alias("name_b".to_owned())]
    );
    assert_eq!(
        parse_darling_alias(&input).unwrap(),
        vec![Alias("name_a".to_owned()), Alias("name_b".to_owned())]
    );
}
