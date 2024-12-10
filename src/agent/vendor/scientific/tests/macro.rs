#![cfg(feature = "macro")]

use scientific::Scientific;

#[test]
fn test_macro() {
  for (sci, string) in [
    (Scientific!(0), "0"),
    (Scientific!(5), "5"),
    (Scientific!(50), "50"),
    (Scientific!(6_000), "6000"),
    (Scientific!(0.23), "0.23"),
    // ensure that the macro is not limited to float precision (even though it's parsed as a float)
    (
      Scientific!(1.0000000000000000000000000000001),
      "1.0000000000000000000000000000001",
    ),
  ] {
    assert_eq!(sci.to_string(), string);
  }
}
