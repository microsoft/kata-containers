use crate::types::builder::Builder;
use crate::types::ptr::Ptr;
use crate::types::sci::Sci;
use crate::types::sign::Sign;
use core::cmp::Ordering;

impl Sci {
  pub(crate) fn sub(&self, rhs: &Sci) -> Sci {
    if rhs.is_zero() {
      self.clone()
    } else if self.is_zero() {
      let mut result = rhs.clone();
      result.neg_assign();
      result
    } else if self.sign != rhs.sign {
      self.nz_add(rhs, self.sign)
    } else {
      match self.compare::<false>(rhs) {
        Ordering::Less => Sci::nz_sub(rhs, self, !rhs.sign),
        Ordering::Equal => Sci::ZERO,
        Ordering::Greater => Sci::nz_sub(self, rhs, self.sign),
      }
    }
  }

  pub(crate) fn nz_sub(&self, rhs: &Sci, sign: Sign) -> Sci {
    let min_exponent = self.exponent.min(rhs.exponent);
    let result_len = self.exponent0() - rhs.exponent;

    let (result, result_ptr) = Builder::new(sign, result_len.max(self.len), min_exponent);

    self.data.copy_to_nonoverlapping(self.len, result_ptr, 0);
    Sci::p_sub(result_ptr, result_len, rhs);
    result.finish()
  }

  // Subtract two mantissa (the exponent and sign is ignored)
  // The first number must be greater or equal to the second
  #[inline]
  pub(crate) fn p_sub(lhs_ptr: Ptr, lhs_len: isize, rhs: &Sci) {
    let mut lhs_cur = lhs_ptr.offset(lhs_len);
    let mut rhs_cur = rhs.data.offset(rhs.len);
    let mut carry = 0;
    while rhs.data < rhs_cur {
      lhs_cur.dec();
      rhs_cur.dec();
      let mut value = *lhs_cur - *rhs_cur - carry;
      if value < 0 {
        value += 10;
        carry = 1;
      } else {
        carry = 0;
      }
      *lhs_cur = value;
    }
    while carry != 0 {
      lhs_cur.dec();
      let mut value = *lhs_cur - carry;
      if value < 0 {
        value += 10;
        carry = 1;
      } else {
        carry = 0;
      }
      *lhs_cur = value;
    }
  }
}
