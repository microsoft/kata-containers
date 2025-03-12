#![cfg(feature = "std")]

use serde_enum_str::{Deserialize_enum_str, Serialize_enum_str};

#[cfg(test)]
mod simple {
    use super::*;

    use core::convert::TryFrom as _;

    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    #[serde(rename_all = "snake_case")]
    enum Foo {
        #[serde(alias = "aa")]
        A,
        #[serde(rename = "B")]
        #[serde(alias = "bb")]
        #[serde(alias = "bbb")]
        B,
        #[serde(skip)]
        C,
        #[serde(skip_serializing)]
        D,
        #[serde(skip_deserializing)]
        E,
        #[serde(other)]
        Other(String),
    }

    #[test]
    fn test_ser() {
        assert_eq!(serde_json::to_string(&Foo::A).unwrap(), r#""a""#);
        assert_eq!(serde_json::to_string(&Foo::B).unwrap(), r#""B""#);
        assert!(serde_json::to_string(&Foo::C)
            .err()
            .unwrap()
            .to_string()
            .contains("::C cannot be serialized"));
        assert!(serde_json::to_string(&Foo::D)
            .err()
            .unwrap()
            .to_string()
            .contains("::D cannot be serialized"));
        assert_eq!(serde_json::to_string(&Foo::E).unwrap(), r#""e""#);
        assert_eq!(
            serde_json::to_string(&Foo::Other("z".to_owned())).unwrap(),
            r#""z""#
        );
    }

    #[test]
    fn test_de() {
        assert_eq!(serde_json::from_str::<Foo>(r#""a""#).unwrap(), Foo::A);
        assert_eq!(serde_json::from_str::<Foo>(r#""aa""#).unwrap(), Foo::A);
        assert_eq!(serde_json::from_str::<Foo>(r#""B""#).unwrap(), Foo::B);
        assert_eq!(serde_json::from_str::<Foo>(r#""bb""#).unwrap(), Foo::B);
        assert_eq!(serde_json::from_str::<Foo>(r#""bbb""#).unwrap(), Foo::B);
        assert_eq!(
            serde_json::from_str::<Foo>(r#""c""#).unwrap(),
            Foo::Other("c".to_owned())
        );
        assert_eq!(serde_json::from_str::<Foo>(r#""d""#).unwrap(), Foo::D);
        assert_eq!(
            serde_json::from_str::<Foo>(r#""e""#).unwrap(),
            Foo::Other("e".to_owned())
        );
        assert_eq!(
            serde_json::from_str::<Foo>(r#""z""#).unwrap(),
            Foo::Other("z".to_owned())
        );
    }

    #[test]
    fn test_to_string() {
        assert_eq!(Foo::A.to_string(), "a");
        assert_eq!(Foo::B.to_string(), "B");
        assert_eq!(Foo::C.to_string(), "c");
        assert_eq!(Foo::D.to_string(), "d");
        assert_eq!(Foo::E.to_string(), "e");
        assert_eq!(Foo::Other("z".to_owned()).to_string(), "z");
    }

    #[test]
    fn test_from_str() {
        assert_eq!("a".parse::<Foo>().unwrap(), Foo::A);
        assert_eq!("aa".parse::<Foo>().unwrap(), Foo::A);
        assert_eq!("B".parse::<Foo>().unwrap(), Foo::B);
        assert_eq!("bb".parse::<Foo>().unwrap(), Foo::B);
        assert_eq!("bbb".parse::<Foo>().unwrap(), Foo::B);
        assert_eq!("c".parse::<Foo>().unwrap(), Foo::Other("c".to_owned()));
        assert_eq!("d".parse::<Foo>().unwrap(), Foo::D);
        assert_eq!("e".parse::<Foo>().unwrap(), Foo::Other("e".to_owned()));
        assert_eq!("z".parse::<Foo>().unwrap(), Foo::Other("z".to_owned()));
    }

    #[test]
    fn test_try_from_string() {
        assert_eq!(Foo::try_from("a".to_owned()).unwrap(), Foo::A);
    }

    #[test]
    fn test_try_from_str() {
        assert_eq!(Foo::try_from("a").unwrap(), Foo::A);
    }
}

#[cfg(test)]
mod without_rename {
    use super::*;

    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    enum Foo {
        A,
        B,
        #[serde(other)]
        Other(String),
    }

    #[test]
    fn test_ser() {
        assert_eq!(serde_json::to_string(&Foo::A).unwrap(), r#""A""#);
        assert_eq!(serde_json::to_string(&Foo::B).unwrap(), r#""B""#);
        assert_eq!(
            serde_json::to_string(&Foo::Other("c".to_owned())).unwrap(),
            r#""c""#
        );
    }

    #[test]
    fn test_de() {
        assert_eq!(serde_json::from_str::<Foo>(r#""A""#).unwrap(), Foo::A);
        assert_eq!(serde_json::from_str::<Foo>(r#""B""#).unwrap(), Foo::B);
        assert_eq!(
            serde_json::from_str::<Foo>(r#""c""#).unwrap(),
            Foo::Other("c".to_owned())
        );
    }
}

#[cfg(test)]
mod without_other {
    use super::*;

    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    #[serde(rename_all = "snake_case")]
    enum Foo {
        A,
        #[serde(rename = "B")]
        B,
    }

    #[test]
    fn test_ser() {
        assert_eq!(serde_json::to_string(&Foo::A).unwrap(), r#""a""#);
        assert_eq!(serde_json::to_string(&Foo::B).unwrap(), r#""B""#);
    }

    #[test]
    fn test_de() {
        assert_eq!(serde_json::from_str::<Foo>(r#""a""#).unwrap(), Foo::A);
        assert_eq!(serde_json::from_str::<Foo>(r#""B""#).unwrap(), Foo::B);
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod with_from_str_other {
    use super::*;

    use std::net::Ipv4Addr;

    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    enum Foo {
        A,
        #[serde(other)]
        Other(Ipv4Addr),
    }

    #[test]
    fn test_ser() {
        assert_eq!(serde_json::to_string(&Foo::A).unwrap(), r#""A""#);
        assert_eq!(
            serde_json::to_string(&Foo::Other(Ipv4Addr::new(127, 0, 0, 1))).unwrap(),
            r#""127.0.0.1""#
        );
    }

    #[test]
    fn test_de() {
        assert_eq!(serde_json::from_str::<Foo>(r#""A""#).unwrap(), Foo::A);
        assert_eq!(
            serde_json::from_str::<Foo>(r#""127.0.0.1""#).unwrap(),
            Foo::Other(Ipv4Addr::new(127, 0, 0, 1))
        );
    }
}

#[cfg(test)]
mod with_independent_rename_all {
    use super::*;

    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    #[serde(rename_all(serialize = "snake_case", deserialize = "UPPERCASE"))]
    enum Foo {
        A,
    }

    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    #[serde(rename_all(serialize = "snake_case"))]
    enum Bar {
        A,
    }

    #[test]
    fn test_ser() {
        assert_eq!(serde_json::to_string(&Foo::A).unwrap(), r#""a""#);
        assert_eq!(serde_json::to_string(&Bar::A).unwrap(), r#""a""#);
    }

    #[test]
    fn test_de() {
        assert_eq!(serde_json::from_str::<Foo>(r#""A""#).unwrap(), Foo::A);
        assert_eq!(serde_json::from_str::<Bar>(r#""A""#).unwrap(), Bar::A);
    }
}

#[cfg(test)]
mod with_independent_rename {
    use super::*;

    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    enum Foo {
        #[serde(rename(serialize = "aa", deserialize = "AA"))]
        A,
    }
    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    enum Bar {
        #[serde(rename(serialize = "aa"))]
        A,
    }

    #[test]
    fn test_ser() {
        assert_eq!(serde_json::to_string(&Foo::A).unwrap(), r#""aa""#);
        assert_eq!(serde_json::to_string(&Bar::A).unwrap(), r#""aa""#);
    }

    #[test]
    fn test_de() {
        assert_eq!(serde_json::from_str::<Foo>(r#""AA""#).unwrap(), Foo::A);
        assert_eq!(serde_json::from_str::<Bar>(r#""A""#).unwrap(), Bar::A);
    }
}

#[cfg(test)]
mod with_unit_other {
    use super::*;

    #[derive(Deserialize_enum_str, Serialize_enum_str, PartialEq, Debug)]
    enum Foo {
        A,
        #[serde(other)]
        Other,
    }

    #[test]
    fn test_ser() {
        assert_eq!(serde_json::to_string(&Foo::A).unwrap(), r#""A""#);
        assert_eq!(serde_json::to_string(&Foo::Other).unwrap(), r#""Other""#);
    }

    #[test]
    fn test_de() {
        assert_eq!(serde_json::from_str::<Foo>(r#""A""#).unwrap(), Foo::A);
        assert_eq!(
            serde_json::from_str::<Foo>(r#""Other""#).unwrap(),
            Foo::Other
        );
        assert_eq!(serde_json::from_str::<Foo>(r#""foo""#).unwrap(), Foo::Other);
    }
}

#[cfg(test)]
mod with_attrs {
    use super::*;

    #[derive(Deserialize_enum_str, Serialize_enum_str, Debug, PartialEq, Eq)]
    enum Foo {
        #[allow(non_camel_case_types)]
        ON_HOLD,
    }
}

#[cfg(test)]
mod with_box_str {
    use super::*;

    #[derive(Deserialize_enum_str, Serialize_enum_str, Debug, PartialEq, Eq)]
    enum Foo {
        A,
        #[serde(other)]
        Other(Box<str>),
    }
}
