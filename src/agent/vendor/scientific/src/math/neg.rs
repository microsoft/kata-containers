use crate::types::sci::Sci;

impl Sci {
  #[inline]
  pub(crate) fn neg_assign(&mut self) {
    self.sign = !self.sign;
  }
}
