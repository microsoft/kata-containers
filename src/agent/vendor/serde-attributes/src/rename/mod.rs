//! [Official doc](https://serde.rs/container-attrs.html#rename)

use alloc::string::String;

#[cfg(feature = "with-darling")]
pub mod darling;
#[cfg(feature = "with-syn")]
pub mod syn;

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub enum Rename {
    Normal(String),
    Independent(RenameIndependent),
}
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub enum RenameIndependent {
    Serialize(String),
    Deserialize(String),
    Both {
        serialize: String,
        deserialize: String,
    },
}
impl Rename {
    pub fn ser_name(&self) -> Option<&str> {
        match self {
            Self::Normal(name)
            | Self::Independent(RenameIndependent::Serialize(name))
            | Self::Independent(RenameIndependent::Both {
                serialize: name,
                deserialize: _,
            }) => Some(name),
            _ => None,
        }
    }

    pub fn de_name(&self) -> Option<&str> {
        match self {
            Self::Normal(name)
            | Self::Independent(RenameIndependent::Deserialize(name))
            | Self::Independent(RenameIndependent::Both {
                serialize: _,
                deserialize: name,
            }) => Some(name),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ser_name_and_de_name() {
        assert_eq!(Rename::Normal("foo".into()).ser_name(), Some("foo"));
        assert_eq!(Rename::Normal("foo".into()).de_name(), Some("foo"));

        assert_eq!(
            Rename::Independent(RenameIndependent::Serialize("ser".into())).ser_name(),
            Some("ser")
        );
        assert_eq!(
            Rename::Independent(RenameIndependent::Serialize("ser".into())).de_name(),
            None
        );

        assert_eq!(
            Rename::Independent(RenameIndependent::Deserialize("de".into())).ser_name(),
            None
        );
        assert_eq!(
            Rename::Independent(RenameIndependent::Deserialize("de".into())).de_name(),
            Some("de")
        );

        assert_eq!(
            Rename::Independent(RenameIndependent::Both {
                serialize: "ser".into(),
                deserialize: "de".into(),
            })
            .ser_name(),
            Some("ser")
        );
        assert_eq!(
            Rename::Independent(RenameIndependent::Both {
                serialize: "ser".into(),
                deserialize: "de".into(),
            })
            .de_name(),
            Some("de")
        );
    }
}
