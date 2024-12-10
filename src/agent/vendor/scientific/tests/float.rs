#![allow(clippy::zero_prefixed_literal)]

use crate::float_common::test_float;
use core::fmt::Debug;
use core::ops::Neg;
use core::str::FromStr;
use scientific::Scientific;

mod float_common;

const POSITIVE_NUMBERS: [f64; 32] = [
  9_223_372_036_854_775_807.0, // 1<<63-1, i64::MAX
  5_000_000_000_000_000_000.1,
  5_000_000_000_000_050_000.0,
  5_000_000_000_000_000_000.0,
  2_000_000_000_000_000_000.0,
  1_000_000_000_000_000_000.0,
  0_576_688_696_100_104_512.0,
  0_555_555_555_555_555_555.0,
  0_368_664_834_771_612_712.0,
  0_004_623_903_520_983_798.0,
  0_000_000_070_000_000_000.0,
  0_000_000_040_000_000_000.0,
  0_000_000_010_000_000_000.0,
  0_000_000_000_799_165_882.0,
  0_000_000_000_525_731_755.0,
  0_000_000_000_000_041_403.0,
  0_000_000_000_000_000_100.0,
  0_000_000_000_000_000_070.0,
  0_000_000_000_000_000_010.0,
  0_000_000_000_000_000_005.0,
  0_000_000_000_000_000_004.0,
  0_000_000_000_000_000_003.0,
  0_000_000_000_000_000_002.0,
  0_000_000_000_000_000_001.0,
  0_000_000_000_000_000_000.0,
  7e100,
  3e100,
  1e100,
  7e-100,
  3e-100,
  1e-100,
  0.1,
];

#[test]
fn float() {
  test_float(
    POSITIVE_NUMBERS
      .iter()
      .copied()
      .chain(POSITIVE_NUMBERS.iter().map(Neg::neg)),
    &[0, 1, 2, 10, 100],
    true,
  );
}

#[test]
fn float_conversion() {
  float_conversion_inner::<f32>();
  float_conversion_inner::<f64>();
}
fn float_conversion_inner<N>()
where
  N: Copy + Debug + FromStr + PartialEq,
  <N as FromStr>::Err: Debug,
  N: for<'a> From<&'a scientific::Scientific>,
  Scientific: TryFrom<N>,
{
  for x in [
    "-128", "0", "128", "-1e-1000", "1e-1000", "1e1000", "-1e1000",
  ] {
    let s = Scientific::from_string(x.to_string()).unwrap();
    let n = N::from_str(x).unwrap();
    assert_eq!(n, N::from(&s));
    if let Ok(n2s) = Scientific::try_from(n) {
      assert_eq!(n, N::from(&n2s));
    }
  }
}
