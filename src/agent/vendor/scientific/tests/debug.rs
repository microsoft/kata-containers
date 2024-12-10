use scientific::Scientific;
use std::str::FromStr;

#[test]
fn display() {
  for number in [("0"), ("5e-1"), ("5"), ("-5"), ("555"), ("555e2")] {
    assert_eq!(
      Scientific::from_str(number).map(|x| format!("{x:?}")),
      Ok(number.to_string())
    );
  }
}
