use crate::types::precision::Precision;
use crate::types::sci::Sci;

impl Sci {
  pub(crate) fn truncate_assign(&mut self, precision: Precision) {
    let len = self.precision_len(precision);
    if self.len > len {
      self.exponent += self.len - len;
      self.len = len; // len may be zero or negative

      // remove trailing zeroes
      while self.len > 0 && self.data[self.len - 1] == 0 {
        self.len -= 1;
        self.exponent += 1;
      }

      if self.len <= 0 {
        self.assign_zero();
      }
    }
  }
}
