use crate::types::sci::Sci;
#[cfg(feature = "debug")]
use core::fmt::Debug;
use core::fmt::{Formatter, Write};

impl Sci {
  pub(crate) fn debug(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    if self.is_zero() {
      return f.write_char('0');
    }
    if self.sign.is_negative() {
      f.write_char('-')?;
    }
    self.data.write_chars(f, 0..self.len)?;
    if self.exponent != 0 {
      write!(f, "e{}", self.exponent)?;
    }
    Ok(())
  }
}

#[cfg(feature = "debug")]
impl Debug for Sci {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    self.debug(f)
  }
}
