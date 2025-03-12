use scientific::Scientific;
use std::ops::{Neg, Shl, ShlAssign, Shr, ShrAssign};
use std::str::FromStr;

#[test]
fn assign() {
  for sci in [
    Scientific::from_str("-5").unwrap(),
    Scientific::from_str("2").unwrap(),
    Scientific::from_str("2356.223").unwrap(),
    Scientific::from_str("23456e44").unwrap(),
  ] {
    let mut a = sci.clone();
    a.neg_assign();
    let b = sci.neg();
    assert_eq!(a, b, "neg");

    let mut a = sci.clone();
    a.abs_assign();
    let b = sci.abs();
    assert_eq!(a, b, "abs");

    let mut a = sci.clone();
    a.shl_assign(1);
    let b = sci.shl(1);
    assert_eq!(a, b, "shl");

    let mut a = sci.clone();
    a.shr_assign(2);
    let b = sci.shr(2);
    assert_eq!(a, b, "shr");
  }
}
