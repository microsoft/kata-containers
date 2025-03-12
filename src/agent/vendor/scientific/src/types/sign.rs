use core::ops::{BitXor, Not};

#[derive(Eq, PartialEq, Copy, Clone)]
pub(crate) struct Sign(bool);
impl Sign {
  pub(crate) const POSITIVE: Sign = Sign(false);
  pub(crate) const NEGATIVE: Sign = Sign(true);

  #[inline]
  pub(crate) const fn is_negative(self) -> bool {
    self.0
  }

  #[inline]
  pub(crate) const fn new(is_negative: bool) -> Sign {
    Sign(is_negative)
  }
}

impl Not for Sign {
  type Output = Self;

  #[inline]
  fn not(self) -> Self::Output {
    Sign(!self.0)
  }
}

impl BitXor for Sign {
  type Output = Sign;

  #[inline]
  fn bitxor(self, rhs: Self) -> Self::Output {
    Sign(self.0 != rhs.0)
  }
}
