use crate::types::sci::Sci;
use core::hash::{Hash, Hasher};

impl Sci {
  pub(crate) fn hash<H: Hasher>(&self, state: &mut H) {
    // it is important to always hash at least something because otherwise
    // calling hash would not change it and it's not distinguishable if such
    // a call was made or not
    if !self.is_zero() {
      // the sign is undefined for zero (could be either pos or neg)
      (self.sign.is_negative()).hash(state);
      // data is not allowed to be accessed for zero
      Hash::hash_slice(self.data.as_slice(self.len), state);
    }
    // exponent is always 1 for zero and thus consistent
    self.exponent.hash(state);
  }
}
