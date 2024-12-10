use crate::types::sci::Sci;
use core::fmt::{Formatter, Write};

impl Sci {
  pub(crate) fn nz_display<W: Write>(&self, f: &mut W) -> Result<(), core::fmt::Error> {
    if self.sign.is_negative() {
      f.write_char('-')?;
    }
    let exp = self.exponent0();
    #[allow(clippy::manual_range_contains)]
    if exp >= -1 && exp <= 0 {
      f.write_char('0')?;
      f.write_char('.')?;
      for _ in exp..0 {
        f.write_char('0')?;
      }
      self.data.write_chars(f, 0..self.len)?;
    } else if exp > 1 && exp <= 7 {
      let mid = exp.min(self.len);
      self.data.write_chars(f, 0..mid)?;
      for _ in mid..exp {
        f.write_char('0')?;
      }
      if self.len > exp {
        f.write_char('.')?;
        self.data.write_chars(f, exp..self.len)?;
      }
    } else {
      self.data.write_char(f, 0)?;
      if self.len > 1 {
        f.write_char('.')?;
        self.data.write_chars(f, 1..self.len)?;
      }
      if exp != 1 {
        write!(f, "e{}", exp - 1)?;
      }
    }
    Ok(())
  }

  pub(crate) fn display(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    if self.is_zero() {
      f.write_char('0')
    } else {
      self.nz_display(f)
    }
  }
}
