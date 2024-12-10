use crate::types::conversion_error::ConversionError;
use crate::types::error::Error;
use crate::types::precision::Precision;
use crate::types::rounding::Rounding;
use crate::types::rounding_mode::RoundingMode;
use crate::types::rounding_rpsp::RPSP;
use crate::types::sci::Sci;
use crate::types::sign::Sign;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt::{Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::ops::{Add, Mul, Neg, Shl, ShlAssign, Shr, ShrAssign, Sub};
use core::str::FromStr;

/// Arbitrary precision scientific number
///
/// See the [module-level documentation](crate) for more details.
#[derive(Clone)]
#[must_use]
#[repr(transparent)]
pub struct Scientific {
  pub(crate) inner: Sci,
}

impl Scientific {
  // This constant must not change before 0.6 since scientific-macro depends on it.
  /// A value of zero.
  pub const ZERO: Scientific = Scientific { inner: Sci::ZERO };

  /// A value of one.
  pub const ONE: Scientific = Scientific { inner: Sci::ONE };

  #[inline]
  /// Convert an [`String`] into a value.
  ///
  /// This does consume the String and does not require allocation.
  ///
  /// # Errors
  ///
  /// Will return [`ConversionError::ParseError`] if the string is invalid.
  pub fn from_string(source: String) -> Result<Scientific, ConversionError> {
    Ok(Scientific {
      inner: Sci::from_string(source)?,
    })
  }

  /// Convert a value into a compressed binary format.
  #[inline]
  #[must_use]
  pub fn to_bytes(&self) -> Vec<u8> {
    self.inner.to_bytes()
  }

  /// Convert a compressed binary format into a value.
  #[inline]
  pub fn from_bytes(bytes: &[u8]) -> Result<Scientific, ConversionError> {
    Ok(Scientific {
      inner: Sci::from_bytes(bytes)?,
    })
  }

  /// Return a reference to the mantissa.
  #[inline]
  #[must_use]
  pub fn as_raw_mantissa(&self) -> &[u8] {
    self.inner.as_raw_mantissa()
  }

  /// Convert raw parts into an value.
  ///
  /// # Errors
  ///
  /// Will return [`ConversionError::ParseError`] if the mantissa contains values other than 0..=9.
  #[inline]
  pub fn from_raw_parts(
    negative: bool,
    mantissa: Vec<u8>,
    exponent: isize,
  ) -> Result<Scientific, ConversionError> {
    Ok(Scientific {
      inner: Sci::from_raw_parts(negative, mantissa, exponent)?,
    })
  }

  /// Returns the square root of an number, truncating.
  ///
  /// The square root will be calculated up to a given precision.
  #[inline]
  pub fn sqrt_truncate(&self, precision: Precision) -> Result<Scientific, Error> {
    Ok(Scientific {
      inner: self.inner.sqrt(precision, false)?,
    })
  }

  /// Returns the square root of an number, rounding.
  ///
  /// The square root will be calculated up to a given precision, but correctly
  /// rounded.
  ///
  /// As all RPSP functions it calculates one more digit than requested for simpler
  /// usage of the final rounding.
  #[inline]
  pub fn sqrt_rpsp(&self, precision: Precision) -> Result<Scientific, Error> {
    Ok(Scientific {
      inner: self.inner.sqrt(precision + 1, true)?,
    })
  }

  /// Computes the absolute value.
  #[inline]
  pub fn abs(&self) -> Scientific {
    let mut result = self.clone();
    result.inner.sign = Sign::POSITIVE;
    result
  }

  /// Computes the absolute value, storing it in self.
  #[inline]
  pub fn abs_assign(&mut self) {
    self.inner.sign = Sign::POSITIVE;
  }

  /// Negating the value, storing it in self.
  #[inline]
  pub fn neg_assign(&mut self) {
    self.inner.neg_assign();
  }

  /// Calculate division, truncating.
  ///
  /// Please be aware that `div_truncate` is only calculating digits up to the specified precision.
  ///
  /// For example 509/100 with a precision of 2 digits or 1 decimals will calculate 5.0 and
  /// not 5.1 as it's may be expected with rounding in mind.
  #[inline]
  pub fn div_truncate(&self, rhs: &Scientific, precision: Precision) -> Result<Scientific, Error> {
    Ok(Scientific {
      inner: self.inner.div(&rhs.inner, precision, false)?,
    })
  }

  /// Calculate division and remainder at the same time.
  ///
  /// This will be faster than calculating them separately.
  #[inline]
  pub fn div_rem(&self, rhs: &Scientific) -> Result<(Scientific, Scientific), Error> {
    let (d, r) = self.inner.div_rem(&rhs.inner)?;
    Ok((Scientific { inner: d }, Scientific { inner: r }))
  }

  /// Calculate division with included rpsp (Rounding to Prepare for Shorter Precision)
  ///
  /// Use rpsp (Rounding to Prepare for Shorter Precision) only during internal calculations and
  /// do one "proper" round at the end of all calculations.
  #[inline]
  pub fn div_rpsp(&self, rhs: &Scientific, precision: Precision) -> Result<Scientific, Error> {
    Ok(Scientific {
      inner: self.inner.div(&rhs.inner, precision + 1, true)?,
    })
  }

  /// Truncate the value and store it in self.
  #[inline]
  pub fn truncate_assign(&mut self, precision: Precision) {
    self.inner.truncate_assign(precision);
  }

  /// Truncate the value.
  #[inline]
  pub fn truncate(&self, precision: Precision) -> Scientific {
    let mut r = self.clone();
    r.inner.truncate_assign(precision);
    r
  }

  /// Round the value and store it in self.
  #[inline]
  pub fn round_assign(&mut self, precision: Precision, rounding: Rounding) {
    self
      .inner
      .round_assign(precision, RoundingMode::Rounding(rounding));
  }

  /// Round the value.
  #[inline]
  pub fn round(&self, precision: Precision, rounding: Rounding) -> Scientific {
    let mut r = self.clone();
    r.inner
      .round_assign(precision, RoundingMode::Rounding(rounding));
    r
  }

  /// Round the value with RPSP and store it in self.
  #[inline]
  pub fn round_rpsp_assign(&mut self, precision: Precision) {
    self
      .inner
      .round_assign(precision + 1, RoundingMode::RPSP(RPSP));
  }

  /// Round the value with RPSP.
  #[inline]
  pub fn round_rpsp(&self, precision: Precision) -> Scientific {
    let mut r = self.clone();
    r.inner
      .round_assign(precision + 1, RoundingMode::RPSP(RPSP));
    r
  }

  /// Returns the length of the mantissa.
  ///
  /// Will return length zero for the value zero.
  #[allow(clippy::len_without_is_empty)]
  #[inline]
  #[must_use]
  pub fn len(&self) -> isize {
    self.inner.len
  }

  /// Returns the number of decimals.
  ///
  /// `0.001`/`1e-3` will return 3, `1000`/`1e3` will return -3.
  #[inline]
  #[must_use]
  pub fn decimals(&self) -> isize {
    -self.inner.exponent
  }

  /// Returns the exponent if the mantissa is written directly behind the decimal dot.
  ///
  /// `123` will return `3` (because it was interpreted as `0.123e3`).
  #[inline]
  #[must_use]
  pub fn exponent0(&self) -> isize {
    self.inner.exponent0()
  }

  /// Returns the exponent if the mantissa is written with one digit in front ot the decimal dot.
  ///
  /// `123` will return `2` (because it was interpreted as `1.23e3`).
  #[inline]
  #[must_use]
  pub fn exponent1(&self) -> isize {
    self.inner.exponent1()
  }

  /// Returns the exponent if the mantissa is written directly in front ot the decimal dot.
  ///
  /// `1.23` will return `-2` (because it was interpreted as `123e-2`).
  #[inline]
  #[must_use]
  pub fn exponent(&self) -> isize {
    self.inner.exponent
  }

  /// Raise a number to an integer power.
  #[inline]
  pub fn powi(&self, exponent: usize) -> Scientific {
    Scientific {
      inner: self.inner.powi(exponent),
    }
  }

  /// Returns `true` if the number is zero.
  #[inline]
  #[must_use]
  pub fn is_zero(&self) -> bool {
    self.inner.is_zero()
  }

  /// Returns `true` if the number is positive and not zero.
  #[inline]
  #[must_use]
  pub fn is_sign_positive(&self) -> bool {
    !self.is_zero() && !self.inner.sign.is_negative()
  }

  /// Returns `true` if the number is negative and not zero.
  #[inline]
  #[must_use]
  pub fn is_sign_negative(&self) -> bool {
    !self.is_zero() && self.inner.sign.is_negative()
  }

  // This function must not change before 0.6 since scientific-macro depends on it.
  #[doc(hidden)]
  #[inline]
  pub const fn unchecked_non_zero_static_new(
    is_negative: bool,
    mantissa: &'static [u8],
    exponent: isize,
  ) -> Scientific {
    Scientific {
      inner: Sci::nz_unchecked_static_new(Sign::new(is_negative), mantissa, exponent),
    }
  }
}

#[cfg(feature = "arc")]
#[cfg_attr(docsrs, doc(cfg(feature = "arc")))]
unsafe impl Send for Scientific {}
#[cfg(feature = "arc")]
#[cfg_attr(docsrs, doc(cfg(feature = "arc")))]
unsafe impl Sync for Scientific {}

impl PartialEq for Scientific {
  #[inline]
  fn eq(&self, other: &Self) -> bool {
    self.cmp(other) == Ordering::Equal
  }
}

impl Eq for Scientific {}

impl PartialOrd for Scientific {
  #[inline]
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for Scientific {
  #[inline]
  fn cmp(&self, other: &Self) -> Ordering {
    self.inner.compare::<true>(&other.inner)
  }
}

impl Add for &Scientific {
  type Output = Scientific;

  #[inline]
  fn add(self, rhs: Self) -> Self::Output {
    Scientific {
      inner: self.inner.add(&rhs.inner),
    }
  }
}

impl Mul for &Scientific {
  type Output = Scientific;

  #[inline]
  fn mul(self, rhs: Self) -> Self::Output {
    Scientific {
      inner: self.inner.mul(&rhs.inner),
    }
  }
}

impl Neg for &Scientific {
  type Output = Scientific;

  #[inline]
  fn neg(self) -> Self::Output {
    let mut result = self.clone();
    result.inner.neg_assign();
    result
  }
}

impl Shl<isize> for &Scientific {
  type Output = Scientific;

  #[inline]
  fn shl(self, rhs: isize) -> Self::Output {
    let mut result = self.clone();
    result.inner.shl_assign(rhs);
    result
  }
}

impl ShlAssign<isize> for Scientific {
  #[inline]
  fn shl_assign(&mut self, rhs: isize) {
    self.inner.shl_assign(rhs);
  }
}

impl Shr<isize> for &Scientific {
  type Output = Scientific;

  #[inline]
  fn shr(self, rhs: isize) -> Self::Output {
    let mut result = self.clone();
    result.inner.shr_assign(rhs);
    result
  }
}

impl ShrAssign<isize> for Scientific {
  #[inline]
  fn shr_assign(&mut self, rhs: isize) {
    self.inner.shr_assign(rhs);
  }
}

impl Sub for &Scientific {
  type Output = Scientific;

  #[inline]
  fn sub(self, rhs: Self) -> Self::Output {
    Scientific {
      inner: self.inner.sub(&rhs.inner),
    }
  }
}

impl FromStr for Scientific {
  type Err = ConversionError;

  #[inline]
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(Scientific {
      inner: Sci::from_string(s.to_string())?,
    })
  }
}

impl Debug for Scientific {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    self.inner.debug(f)
  }
}

impl Display for Scientific {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    self.inner.display(f)
  }
}

impl Hash for &Scientific {
  #[inline]
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.inner.hash(state);
  }
}

impl TryFrom<f64> for Scientific {
  type Error = ConversionError;

  fn try_from(value: f64) -> Result<Self, Self::Error> {
    if value.is_finite() {
      Ok(Scientific {
        inner: Sci::from_string(value.to_string())?,
      })
    } else {
      Err(ConversionError::FloatIsNotFinite)
    }
  }
}

impl From<&Scientific> for f64 {
  #[inline]
  fn from(value: &Scientific) -> Self {
    value.inner.to_f64()
  }
}

impl TryFrom<f32> for Scientific {
  type Error = ConversionError;

  fn try_from(value: f32) -> Result<Self, Self::Error> {
    if value.is_finite() {
      Ok(Scientific {
        inner: Sci::from_string(value.to_string())?,
      })
    } else {
      Err(ConversionError::FloatIsNotFinite)
    }
  }
}

impl From<&Scientific> for f32 {
  #[inline]
  fn from(value: &Scientific) -> Self {
    value.inner.to_f32()
  }
}
