use core::fmt::{Display, Formatter};

/// Errors which can occur during conversion.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConversionError {
  /// The float is not finite. (Only for `From<float>` conversion.)
  FloatIsNotFinite,
  /// Number is too large. (Only for `Into<integer>` conversion.)
  NumberTooLarge,
  /// Parse error. (Just not a valid number.)
  ParseError,
  /// Number is negative. (Only for `Into<positive integer>` conversion.)
  NumberIsNegative,
  /// Number is not an integer. (Only for `Into<integer>` conversion.)
  NumberIsNotAnInteger,
  /// Exponent is too large for this platform. (Only used by [Scientific::from_bytes](crate::Scientific::from_bytes).)
  ExponentTooLargeForThisPlatform,
}

impl Display for ConversionError {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    match self {
      ConversionError::FloatIsNotFinite => f.write_str("Float is not finite"),
      ConversionError::NumberTooLarge => f.write_str("Number too large"),
      ConversionError::ParseError => f.write_str("Parse error"),
      ConversionError::NumberIsNegative => f.write_str("Number is negative"),
      ConversionError::NumberIsNotAnInteger => f.write_str("Number is not an integer"),
      ConversionError::ExponentTooLargeForThisPlatform => {
        f.write_str("Exponent is too large for this platform")
      }
    }
  }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for ConversionError {}
