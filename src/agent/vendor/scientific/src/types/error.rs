use core::fmt::{Display, Formatter};

/// Errors which can occur during calculation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
  /// Used by `div`.
  DivisionByZero,
  /// Used by `sqrt`.
  NumberIsNegative,
}

impl Display for Error {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    match self {
      Error::DivisionByZero => f.write_str("Division by zero"),
      Error::NumberIsNegative => f.write_str("Number is negative"),
    }
  }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {}
