use crate::types::sci::Sci;
use core::ops::ShrAssign;

impl Sci {
  pub(crate) fn powi(&self, exponent: usize) -> Sci {
    if exponent == 0 {
      Sci::ONE
    } else if self.is_zero() {
      Sci::ZERO
    } else {
      nz_powi(self, exponent)
    }
  }
}

#[inline]
fn nz_powi(base: &Sci, mut exponent: usize) -> Sci {
  // base is not zero, exponent is greater than zero
  let mut power = base.clone();
  while exponent & 1 == 0 {
    power = power.mul(&power);
    exponent.shr_assign(1);
  }
  let mut result = power.clone();
  exponent.shr_assign(1);

  while exponent > 0 {
    power = power.mul(&power);
    if exponent & 1 != 0 {
      result = result.mul(&power);
    }
    exponent.shr_assign(1);
  }
  result
}
