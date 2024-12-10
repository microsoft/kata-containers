use crate::types::builder::Builder;
use crate::types::error::Error;
use crate::types::owner::Owner;
use crate::types::precision::Precision;
use crate::types::ptr::Ptr;
use crate::types::rounding_mode::RoundingMode;
use crate::types::rounding_rpsp::RPSP;
use crate::types::sci::Sci;
use crate::types::sign::Sign;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::convert::Infallible;

#[inline]
fn div_results_in_zero(lhs: &Sci, rhs: &Sci, precision: Precision) -> bool {
  match precision {
    Precision::Digits(digits) => digits <= 0,
    Precision::Decimals(decimals) => lhs.exponent0() - rhs.exponent0() + decimals < 0,
  }
}

pub(crate) trait Remainder
where
  Self: Sized,
{
  fn has_result() -> bool;
  fn from_zero() -> Option<Self>;
  fn from_sci(sci: &Sci) -> Option<Self>;
  fn from_parts(sign: Sign, vec: Vec<u8>, data: Ptr, len: isize, exponent: isize) -> Option<Self>;
}

impl Remainder for Infallible {
  #[inline]
  fn has_result() -> bool {
    false
  }

  #[inline]
  fn from_zero() -> Option<Self> {
    None
  }

  #[inline]
  fn from_sci(_: &Sci) -> Option<Self> {
    None
  }

  #[inline]
  fn from_parts(_: Sign, _: Vec<u8>, _: Ptr, _: isize, _: isize) -> Option<Self> {
    None
  }
}

impl Remainder for Sci {
  #[inline]
  fn has_result() -> bool {
    true
  }

  #[inline]
  fn from_zero() -> Option<Self> {
    Some(Sci::ZERO)
  }

  #[inline]
  fn from_sci(sci: &Sci) -> Option<Self> {
    Some(sci.clone())
  }

  #[inline]
  fn from_parts(sign: Sign, vec: Vec<u8>, data: Ptr, len: isize, exponent: isize) -> Option<Self> {
    Some(Builder::from_data(
      sign,
      data,
      len,
      exponent,
      Owner::new(vec),
    ))
  }
}

impl Sci {
  // this function is not inlined as the called functions will be inlined
  pub(crate) fn div(&self, rhs: &Sci, precision: Precision, use_rpsp: bool) -> Result<Sci, Error> {
    Ok(self.div_multi::<Infallible>(rhs, precision, use_rpsp)?.0)
  }

  // this function is not inlined as the called functions will be inlined
  pub(crate) fn div_rem(&self, rhs: &Sci) -> Result<(Sci, Sci), Error> {
    let (quot, rem) = self.div_multi::<Sci>(rhs, Precision::INTEGER, false)?;

    let rem = rem.unwrap_or_else(|| self.sub(&quot.mul(rhs)));

    Ok((quot, rem))
  }

  #[inline]
  fn div_multi<R: Remainder>(
    &self,
    rhs: &Sci,
    precision: Precision,
    use_rpsp: bool,
  ) -> Result<(Sci, Option<R>), Error> {
    #[cfg(feature = "debug")]
    assert!(!(R::has_result() && use_rpsp));

    if rhs.is_zero() {
      Err(Error::DivisionByZero)
    } else if self.is_zero() {
      Ok((Sci::ZERO, R::from_zero()))
    } else if div_results_in_zero(self, rhs, precision) {
      if let (true, Precision::Decimals(d)) = (use_rpsp, precision) {
        Ok((Sci::one(self.sign ^ rhs.sign, -d), None))
      } else {
        Ok((Sci::ZERO, R::from_sci(self)))
      }
    } else if rhs.len == 1 && *rhs.data == 1 {
      let mut r = self.clone();
      r.shr_assign(rhs.exponent);
      if use_rpsp {
        r.round_assign(precision, RoundingMode::RPSP(RPSP));
      } else {
        r.truncate_assign(precision);
      }
      if rhs.sign.is_negative() {
        r.neg_assign();
      }
      let remainder = if self.len == r.len {
        // self is the same as the result -> no remainder
        R::from_zero()
      } else {
        // some portions of self is lost due to truncating -> has remainder (to be calculated when needed)
        None
      };
      Ok((r, remainder))
    } else if self.len == rhs.len && self.nz_compare_mantissa::<false>(rhs) == Ordering::Equal {
      Ok((
        Sci::one(self.sign ^ rhs.sign, self.exponent0() - rhs.exponent0()),
        R::from_zero(),
      ))
    } else {
      let mut extra_digits = match precision {
        Precision::Digits(digits) => digits - (self.len - rhs.len),
        Precision::Decimals(decimals) => self.exponent - rhs.exponent + decimals,
      };
      if R::has_result() {
        extra_digits = extra_digits.max(0);
      }
      Ok(nz_div::<R>(self, rhs, extra_digits, precision, use_rpsp))
    }
  }
}

#[inline]
fn nz_div<R: Remainder>(
  lhs: &Sci,
  rhs: &Sci,
  extra_digits: isize,
  precision: Precision,
  use_rpsp: bool,
) -> (Sci, Option<R>) {
  // Notice: extra_digits can be negative!
  // lhs.len + decimals is guaranteed to be >= rhs.len
  #[cfg(feature = "debug")]
  assert!(lhs.len + extra_digits >= rhs.len);

  let mut tmp = vec![0; (lhs.len + extra_digits) as usize];
  let mut tmp_ptr = Ptr::new_mut(tmp.as_mut_slice());
  lhs
    .data
    .copy_to_nonoverlapping(lhs.len + extra_digits.min(0), tmp_ptr, 0);
  let mut tmp_len = 0;
  let (result, mut result_ptr) = Builder::new(
    lhs.sign ^ rhs.sign,
    lhs.len + extra_digits + isize::from(use_rpsp),
    lhs.exponent - rhs.exponent - extra_digits - isize::from(use_rpsp),
  );
  let result_end = result_ptr.offset(lhs.len + extra_digits);
  while result_ptr < result_end {
    tmp_len += 1;
    p_trim(&mut tmp_ptr, &mut tmp_len);
    let mut j = 0;
    while p_ge(tmp_ptr, tmp_len, rhs) {
      Sci::p_sub(tmp_ptr, tmp_len, rhs);
      p_trim(&mut tmp_ptr, &mut tmp_len);
      j += 1;
    }
    *result_ptr = j;
    result_ptr.inc();
  }

  if use_rpsp && (extra_digits < 0 || tmp_len > 0) {
    *result_ptr = 8;
  }

  let mut result = result.finish();

  if use_rpsp {
    result.round_assign(precision, RoundingMode::RPSP(RPSP));
    (result, None)
  } else {
    let orig_len = result.len;
    result.truncate_assign(precision);
    let remainder = if orig_len == result.len {
      R::from_parts(
        lhs.sign,
        tmp,
        tmp_ptr,
        tmp_len,
        rhs.exponent.min(lhs.exponent),
      )
    } else {
      None
    };
    (result, remainder)
  }
}

// Remove leading zeroes, this is important because p_ge assumes that there are no leading zeroes
#[inline]
fn p_trim(value_ptr: &mut Ptr, value_len: &mut isize) {
  while *value_len > 0 && **value_ptr == 0 {
    value_ptr.inc();
    *value_len -= 1;
  }
}

// Compare two mantissa (the exponent and sign is ignored)
#[inline]
fn p_ge(mut lhs_ptr: Ptr, lhs_len: isize, rhs: &Sci) -> bool {
  if lhs_len != rhs.len {
    lhs_len >= rhs.len
  } else {
    let mut rhs_ptr = rhs.data;
    let rhs_end = rhs.data.offset(rhs.len);
    while rhs_ptr < rhs_end {
      if *lhs_ptr != *rhs_ptr {
        return *lhs_ptr >= *rhs_ptr;
      }
      lhs_ptr.inc();
      rhs_ptr.inc();
    }
    true
  }
}
