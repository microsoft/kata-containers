use crate::types::sci::Sci;
use core::cmp::Ordering;

impl Sci {
  pub(crate) fn compare<const USE_SIGN: bool>(&self, rhs: &Sci) -> Ordering {
    #[allow(clippy::collapsible_else_if)]
    if self.is_zero() && rhs.is_zero() {
      Ordering::Equal
    } else if self.is_zero() {
      if USE_SIGN && rhs.sign.is_negative() {
        Ordering::Greater
      } else {
        Ordering::Less
      }
    } else if rhs.is_zero() {
      if USE_SIGN && self.sign.is_negative() {
        Ordering::Less
      } else {
        Ordering::Greater
      }
    } else {
      if USE_SIGN && self.sign != rhs.sign {
        if self.sign.is_negative() {
          Ordering::Less
        } else {
          Ordering::Greater
        }
      } else {
        match self.exponent0().cmp(&rhs.exponent0()) {
          Ordering::Equal => self.nz_compare_mantissa::<USE_SIGN>(rhs),
          ordering => {
            if USE_SIGN && self.sign.is_negative() {
              ordering.reverse()
            } else {
              ordering
            }
          }
        }
      }
    }
  }

  pub(crate) fn nz_compare_mantissa<const USE_SIGN: bool>(&self, rhs: &Sci) -> Ordering {
    let mut lhs_ptr = self.data;
    let mut rhs_ptr = rhs.data;
    let mut count = self.len.min(rhs.len);

    while count > 0 {
      let lhs_value = *lhs_ptr;
      let rhs_value = *rhs_ptr;
      if lhs_value != rhs_value {
        #[allow(clippy::collapsible_else_if)]
        return if lhs_value > rhs_value {
          if USE_SIGN && self.sign.is_negative() {
            Ordering::Less
          } else {
            Ordering::Greater
          }
        } else {
          if USE_SIGN && self.sign.is_negative() {
            Ordering::Greater
          } else {
            Ordering::Less
          }
        };
      }
      lhs_ptr.inc();
      rhs_ptr.inc();
      count -= 1;
    }

    let ordering = self.len.cmp(&rhs.len);
    if USE_SIGN && self.sign.is_negative() {
      ordering.reverse()
    } else {
      ordering
    }
  }
}
