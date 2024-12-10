//! [Official doc](https://serde.rs/container-attrs.html#rename_all)

pub use serde_rename_rule;

use serde_rename_rule::RenameRule;

#[cfg(feature = "with-darling")]
pub mod darling;
#[cfg(feature = "with-syn")]
pub mod syn;

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub enum RenameAll {
    Normal(RenameRule),
    Independent(RenameAllIndependent),
}
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub enum RenameAllIndependent {
    Serialize(RenameRule),
    Deserialize(RenameRule),
    Both {
        serialize: RenameRule,
        deserialize: RenameRule,
    },
}
impl RenameAll {
    pub fn ser_rule(&self) -> Option<&RenameRule> {
        match self {
            Self::Normal(rule)
            | Self::Independent(RenameAllIndependent::Serialize(rule))
            | Self::Independent(RenameAllIndependent::Both {
                serialize: rule,
                deserialize: _,
            }) => Some(rule),
            _ => None,
        }
    }

    pub fn de_rule(&self) -> Option<&RenameRule> {
        match self {
            Self::Normal(rule)
            | Self::Independent(RenameAllIndependent::Deserialize(rule))
            | Self::Independent(RenameAllIndependent::Both {
                serialize: _,
                deserialize: rule,
            }) => Some(rule),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ser_rule_and_de_rule() {
        assert_eq!(
            RenameAll::Normal(RenameRule::SnakeCase).ser_rule(),
            Some(&RenameRule::SnakeCase)
        );
        assert_eq!(
            RenameAll::Normal(RenameRule::SnakeCase).de_rule(),
            Some(&RenameRule::SnakeCase)
        );

        assert_eq!(
            RenameAll::Independent(RenameAllIndependent::Serialize(RenameRule::LowerCase))
                .ser_rule(),
            Some(&RenameRule::LowerCase)
        );
        assert_eq!(
            RenameAll::Independent(RenameAllIndependent::Serialize(RenameRule::LowerCase))
                .de_rule(),
            None
        );

        assert_eq!(
            RenameAll::Independent(RenameAllIndependent::Deserialize(RenameRule::UpperCase))
                .ser_rule(),
            None
        );
        assert_eq!(
            RenameAll::Independent(RenameAllIndependent::Deserialize(RenameRule::UpperCase))
                .de_rule(),
            Some(&RenameRule::UpperCase)
        );

        assert_eq!(
            RenameAll::Independent(RenameAllIndependent::Both {
                serialize: RenameRule::LowerCase,
                deserialize: RenameRule::UpperCase,
            })
            .ser_rule(),
            Some(&RenameRule::LowerCase)
        );
        assert_eq!(
            RenameAll::Independent(RenameAllIndependent::Both {
                serialize: RenameRule::LowerCase,
                deserialize: RenameRule::UpperCase,
            })
            .de_rule(),
            Some(&RenameRule::UpperCase)
        );
    }
}
