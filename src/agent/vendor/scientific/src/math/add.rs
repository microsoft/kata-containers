use crate::types::builder::Builder;
use crate::types::sci::Sci;
use crate::types::sign::Sign;
use core::cmp::Ordering;
use core::mem::swap;

impl Sci {
  pub(crate) fn add(&self, rhs: &Sci) -> Sci {
    if self.is_zero() {
      rhs.clone()
    } else if rhs.is_zero() {
      self.clone()
    } else if self.sign == rhs.sign {
      self.nz_add(rhs, self.sign)
    } else {
      match self.compare::<false>(rhs) {
        Ordering::Less => rhs.nz_sub(self, rhs.sign),
        Ordering::Equal => Sci::ZERO,
        Ordering::Greater => self.nz_sub(rhs, self.sign),
      }
    }
  }

  pub(crate) fn nz_add<'a>(mut self: &'a Self, mut rhs: &'a Sci, sign: Sign) -> Sci {
    let mut lhs_exponent0 = self.exponent0();
    let mut rhs_exponent0 = rhs.exponent0();

    if lhs_exponent0 < rhs_exponent0 {
      swap(&mut self, &mut rhs);
      swap(&mut lhs_exponent0, &mut rhs_exponent0);
    }

    let min_exponent = self.exponent.min(rhs.exponent);
    let result_len = 1 + (lhs_exponent0.max(rhs_exponent0) - min_exponent);

    let (result, mut result_ptr) = Builder::new(sign, result_len, min_exponent);

    let mut carry = 0;

    self.data.copy_to_nonoverlapping(self.len, result_ptr, 1);
    result_ptr = result_ptr.offset(result_len - (rhs.exponent - min_exponent));
    let mut rhs_ptr = rhs.data.offset(rhs.len);
    while rhs.data < rhs_ptr {
      rhs_ptr.dec();
      result_ptr.dec();
      let mut value = *result_ptr + *rhs_ptr + carry;
      if value >= 10 {
        value -= 10;
        carry = 1;
      } else {
        carry = 0;
      }
      *result_ptr = value;
    }

    while carry != 0 {
      result_ptr.dec();
      let mut value = *result_ptr + carry;
      if value == 10 {
        value = 0;
        carry = 1;
      } else {
        carry = 0;
      }
      *result_ptr = value;
    }

    result.finish()
  }
}
