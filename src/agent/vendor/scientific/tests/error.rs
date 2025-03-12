use scientific::{Error, Precision, Scientific};
use std::str::FromStr;

#[test]
fn error() {
  // DivisionByZero
  assert_eq!(
    Scientific::from_str("100")
      .unwrap()
      .div_truncate(&Scientific::from_str("0").unwrap(), Precision::INTEGER),
    Err(Error::DivisionByZero)
  );
  // NumberIsNegative
  assert_eq!(
    Scientific::from_str("-1")
      .unwrap()
      .sqrt_truncate(Precision::INTEGER),
    Err(Error::NumberIsNegative)
  );

  // text
  assert_eq!(&Error::DivisionByZero.to_string(), "Division by zero");
  assert_eq!(&Error::NumberIsNegative.to_string(), "Number is negative");
}
