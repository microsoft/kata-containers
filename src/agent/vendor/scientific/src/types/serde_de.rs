use crate::types::scientific::Scientific;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Formatter;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for Scientific {
  fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
  where
    D: Deserializer<'de>,
  {
    struct SciVisitor;
    impl<'de> Visitor<'de> for SciVisitor {
      type Value = Scientific;

      fn expecting(&self, formatter: &mut Formatter) -> core::fmt::Result {
        formatter.write_str("Scientific")
      }

      fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        Scientific::from_bytes(v).map_err(|bse| serde::de::Error::custom(bse.to_string()))
      }

      fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
      where
        D: Deserializer<'de>,
      {
        deserializer.deserialize_bytes(SciVisitor)
      }

      fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
      where
        A: SeqAccess<'de>,
      {
        let mut buf = match seq.size_hint() {
          None => Vec::new(),
          Some(l) => Vec::with_capacity(l),
        };
        while let Some(e) = seq.next_element()? {
          buf.push(e);
        }
        Scientific::from_bytes(&buf).map_err(|bse| serde::de::Error::custom(bse.to_string()))
      }
    }

    if deserializer.is_human_readable() {
      Scientific::from_string(String::deserialize(deserializer)?)
        .map_err(|err| serde::de::Error::custom(err.to_string()))
    } else {
      deserializer.deserialize_newtype_struct("Scientific", SciVisitor)
    }
  }
}
