use scientific::Precision;

#[test]
fn precision() {
  // digits, add/sub
  assert_eq!(Precision::Digits(1) + 5, Precision::Digits(6));
  assert_eq!(Precision::Digits(5) - 1, Precision::Digits(4));
  // digits, with assign
  let mut p = Precision::Digits(1);
  p += 5;
  assert_eq!(p, Precision::Digits(6));
  let mut p = Precision::Digits(5);
  p -= 1;
  assert_eq!(p, Precision::Digits(4));
  // decimals, add/sub
  assert_eq!(Precision::Decimals(1) + 5, Precision::Decimals(6));
  assert_eq!(Precision::Decimals(5) - 1, Precision::Decimals(4));
  // decimals, with assign
  let mut p = Precision::Decimals(1);
  p += 5;
  assert_eq!(p, Precision::Decimals(6));
  let mut p = Precision::Decimals(5);
  p -= 1;
  assert_eq!(p, Precision::Decimals(4));
}
