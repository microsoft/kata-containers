#![allow(clippy::zero_prefixed_literal)]

use crate::integer_common::test_integer;
use core::fmt::Debug;
use core::ops::Neg;
use core::str::FromStr;
use scientific::{ConversionError, Scientific};

mod integer_common;

const POSITIVE_NUMBERS: [i128; 24] = [
  9_223_372_036_854_775_807, // 1<<63-1, i64::MAX
  5_000_000_000_000_000_000,
  2_000_000_000_000_000_000,
  1_000_000_000_000_000_000,
  1_000_000_000_000_000_001,
  0_576_688_696_100_104_512,
  0_555_555_555_555_555_555,
  0_368_664_834_771_612_712,
  0_004_623_903_520_983_798,
  0_000_000_070_000_000_000,
  0_000_000_040_000_000_000,
  0_000_000_010_000_000_000,
  0_000_000_000_799_165_882,
  0_000_000_000_525_731_755,
  0_000_000_000_000_041_403,
  0_000_000_000_000_000_100,
  0_000_000_000_000_000_070,
  0_000_000_000_000_000_010,
  0_000_000_000_000_000_005,
  0_000_000_000_000_000_004,
  0_000_000_000_000_000_003,
  0_000_000_000_000_000_002,
  0_000_000_000_000_000_001,
  0_000_000_000_000_000_000,
];

#[test]
fn integer() {
  test_integer(
    POSITIVE_NUMBERS
      .iter()
      .copied()
      .chain(POSITIVE_NUMBERS.iter().map(Neg::neg)),
    100,
    true,
  );
}

#[test]
fn integer_conversion() {
  integer_conversion_inner::<i8, true>();
  integer_conversion_inner::<u8, false>();
  integer_conversion_inner::<i16, true>();
  integer_conversion_inner::<u16, false>();
  integer_conversion_inner::<i32, true>();
  integer_conversion_inner::<u32, false>();
  integer_conversion_inner::<i64, true>();
  integer_conversion_inner::<u64, false>();
  integer_conversion_inner::<i128, true>();
  integer_conversion_inner::<u128, false>();
  integer_conversion_inner::<isize, true>();
  integer_conversion_inner::<usize, false>();
}

fn integer_conversion_inner<N, const SIGNED: bool>()
where
  N: Debug + FromStr + PartialEq,
  N: for<'a> TryFrom<&'a scientific::Scientific, Error = ConversionError>,
  Scientific: From<N>,
{
  for x in [
    "0",
    // i8
    "-129",
    "-128",
    "127",
    "128",
    // u8
    "255",
    "256",
    // i16
    "-32769",
    "-32768",
    "32767",
    "32768",
    // u16
    "65535",
    "65536",
    // i32
    "-2147483649",
    "-2147483648",
    "2147483647",
    "2147483648",
    // u32
    "4294967295",
    "4294967296",
    // i64
    "-9223372036854775809",
    "-9223372036854775808",
    "9223372036854775807",
    "9223372036854775808",
    // u64
    "18446744073709551615",
    "18446744073709551616",
  ] {
    let s = Scientific::from_string(x.to_string()).unwrap();
    let n = N::from_str(x).map_err(|_| {
      if SIGNED || s.is_sign_positive() {
        ConversionError::NumberTooLarge
      } else {
        ConversionError::NumberIsNegative
      }
    });
    assert_eq!(n, N::try_from(&s));
    if let Ok(n) = n {
      assert_eq!(s, Scientific::from(n));
    }
  }
}
