use crate::types::sci::Sci;
use crate::types::sign::Sign;
use alloc::string::String;
use core::fmt::Write;
use core::str::FromStr;

impl Sci {
  pub(crate) fn to_f64(&self) -> f64 {
    if self.is_zero() {
      0f64
    } else if self.exponent1() > f64::MAX_10_EXP as isize {
      match self.sign {
        Sign::POSITIVE => f64::INFINITY,
        Sign::NEGATIVE => f64::NEG_INFINITY,
      }
    } else if self.exponent1() < f64::MIN_10_EXP as isize {
      0f64
    } else {
      const DIGITS: isize = 18;
      let mut str = String::with_capacity(6 + DIGITS as usize);
      if self.sign.is_negative() {
        str.push('-');
      }
      self
        .data
        .write_chars(&mut str, 0..self.len.min(DIGITS))
        .expect("writing to String should not fail");
      write!(&mut str, "e{}", self.exponent + (self.len - DIGITS).max(0))
        .expect("writing to String should not fail");
      f64::from_str(&str).unwrap()
    }
  }

  pub(crate) fn to_f32(&self) -> f32 {
    if self.is_zero() {
      0f32
    } else if self.exponent1() > f32::MAX_10_EXP as isize {
      match self.sign {
        Sign::POSITIVE => f32::INFINITY,
        Sign::NEGATIVE => f32::NEG_INFINITY,
      }
    } else if self.exponent1() < f32::MIN_10_EXP as isize {
      0f32
    } else {
      const DIGITS: isize = 10;
      let mut str = String::with_capacity(6 + DIGITS as usize);
      if self.sign.is_negative() {
        str.push('-');
      }
      self
        .data
        .write_chars(&mut str, 0..self.len.min(DIGITS))
        .expect("writing to String should not fail");
      write!(&mut str, "e{}", self.exponent + (self.len - DIGITS).max(0))
        .expect("writing to String should not fail");
      f32::from_str(&str).unwrap()
    }
  }
}
