use crate::types::builder::Builder;
use crate::types::conversion_error::ConversionError;
use crate::types::owner::Owner;
use crate::types::ptr::Ptr;
use crate::types::sci::Sci;
use crate::types::sign::Sign;
use alloc::vec::Vec;

pub(crate) const MANTISSA_0: [u8; 1] = [0];

impl Sci {
  pub(crate) fn as_raw_mantissa(&self) -> &[u8] {
    if self.is_zero() {
      // value.data is undefined for zero
      // should a pointer to an empty slice be returned?
      &MANTISSA_0
    } else {
      self.data.as_slice(self.len)
    }
  }

  pub(crate) fn from_raw_parts(
    is_negative: bool,
    mantissa: Vec<u8>,
    exponent: isize,
  ) -> Result<Sci, ConversionError> {
    for v in mantissa.iter() {
      if *v > 9 {
        return Err(ConversionError::ParseError);
      }
    }

    let len = mantissa.len() as isize;
    Ok(Builder::from_data(
      Sign::new(is_negative),
      Ptr::new(mantissa.as_slice()),
      len,
      exponent,
      Owner::new(mantissa),
    ))
  }
}
