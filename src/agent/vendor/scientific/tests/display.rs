use scientific::Scientific;
use std::str::FromStr;

#[test]
fn display() {
  for number in [
    ("0"),
    ("0.5"),
    ("0.05"),
    ("555"),
    ("-555"),
    ("555.555"),
    ("555.555666"),
    ("4.555555666"),
  ] {
    assert_eq!(
      Scientific::from_str(number).map(|x| ToString::to_string(&x)),
      Ok(number.to_string())
    );
  }
}
