use crate::types::sci::Sci;
use crate::types::scientific::Scientific;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Serialize, Serializer};

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for Scientific {
  fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
  where
    S: Serializer,
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&display_to_string(&self.inner))
    } else {
      serializer.serialize_newtype_struct("Scientific", {
        struct SW(Vec<u8>);

        impl Serialize for SW {
          fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
          where
            S: Serializer,
          {
            serializer.serialize_bytes(&self.0)
          }
        }

        &SW(self.to_bytes())
      })
    }
  }
}

fn display_to_string(value: &Sci) -> String {
  if value.is_zero() {
    return "0".to_string();
  }
  let mut result = String::with_capacity(value.len as usize + 7);
  value
    .nz_display(&mut result)
    .expect("writing to String should not fail");
  result
}
