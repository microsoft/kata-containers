use core::convert::TryFrom;
use num_integer::Roots;
use rand::prelude::SliceRandom;
use scientific::{Decimals, Error, Precision, Scientific};

#[allow(clippy::type_complexity)]
const FUNCTIONS: [(
  &str,
  fn(i128, i128) -> Result<i128, Error>,
  fn(&Scientific, &Scientific) -> Result<Scientific, Error>,
); 5] = [
  ("add", |a, b| Ok(a + b), |a, b| Ok(a + b)),
  ("sub", |a, b| Ok(a - b), |a, b| Ok(a - b)),
  ("mul", |a, b| Ok(a * b), |a, b| Ok(a * b)),
  ("div", int_div, |a, b| a.div_truncate(b, Precision::INTEGER)),
  ("rem", int_rem, |a, b| a.div_rem(b).map(|(_, r)| r)),
];

fn int_div(a: i128, b: i128) -> Result<i128, Error> {
  if b == 0 {
    Err(Error::DivisionByZero)
  } else {
    Ok(a / b)
  }
}

fn int_rem(a: i128, b: i128) -> Result<i128, Error> {
  if b == 0 {
    Err(Error::DivisionByZero)
  } else {
    Ok(a % b)
  }
}

pub(crate) fn test_integer<I>(numbers: I, sqrt_decimals: isize, randomize: bool)
where
  I: Iterator<Item = i128>,
{
  let mut numbers = numbers
    .map(|n| (n, Scientific::from(n)))
    .collect::<Vec<(i128, Scientific)>>();

  if randomize {
    // to increase the chance that an error is caught earlier
    let mut rng = rand::thread_rng();
    numbers.shuffle(&mut rng);
  }

  for (int_a, sci_a) in numbers.iter() {
    for (int_b, sci_b) in numbers.iter() {
      // several functions
      for (name, int_fn, sci_fn) in FUNCTIONS.iter() {
        let int_result = int_fn(*int_a, *int_b);
        let sci_result = sci_fn(sci_a, sci_b);
        assert_eq!(
          int_result.map(|i| Scientific::from_string(i.to_string()).unwrap()),
          sci_result,
          "function {name}({int_a}, {int_b}) -> {int_result:?} = {sci_result:?}",
        );
      }
      // compare
      let int_result = int_a.cmp(int_b);
      let sci_result = sci_a.cmp(sci_b);
      assert_eq!(
        int_result, sci_result,
        "function {}({}, {}) -> {:?} = {:?}",
        "cmp", int_a, int_b, int_result, sci_result,
      );
      // div_rpsp
      let big = sci_a.div_truncate(sci_b, Decimals(20)).map(|mut b| {
        b.round_rpsp_assign(Decimals(1));
        b
      });
      let fast = sci_a.div_rpsp(sci_b, Decimals(1));
      assert_eq!(big, fast, "div_rpsp vs. div_truncate and round_rpsp");
      // div_truncate
      let big = sci_a.div_rpsp(sci_b, Decimals(1)).map(|mut b| {
        b.truncate_assign(Decimals(1));
        b
      });
      let fast = sci_a.div_truncate(sci_b, Decimals(1));
      assert_eq!(big, fast, "div_truncate vs. div_rpsp and truncate");
    }
    // i128 via string
    let i2s = sci_a;
    let i2s_str = Scientific::from_string(int_a.to_string()).unwrap();
    assert_eq!(i2s, &i2s_str, "conversion from i128");
    // i128
    let s2i = i128::try_from(i2s);
    assert_eq!(Ok(*int_a), s2i, "conversion from/to i128");
    // i64
    let i2s = Scientific::from(*int_a as i64);
    let s2i = i64::try_from(&i2s);
    assert_eq!(Ok(*int_a as i64), s2i, "conversion from/to i64");
    // i32
    let i2s = Scientific::from(*int_a as i32);
    let s2i = i32::try_from(&i2s);
    assert_eq!(Ok(*int_a as i32), s2i, "conversion from/to i32");
    // sqrt
    if *int_a >= 0 {
      // v1
      let sci_cubed = sci_a * sci_a;
      let sci_result = sci_cubed.sqrt_truncate(Decimals(sqrt_decimals));
      assert_eq!(
        Ok(sci_a.clone()),
        sci_result,
        "function {}({}) -> {:?} = {:?}",
        "sqrt_v1",
        int_a * int_a,
        int_a,
        sci_result,
      );
      // v1.2
      let sci_cubed = sci_a * sci_a;
      let sci_result = sci_cubed.sqrt_rpsp(Decimals(1));
      assert_eq!(
        Ok(sci_a.clone()),
        sci_result,
        "function {}({}) -> {:?} = {:?}",
        "sqrt_v1.2",
        int_a * int_a,
        int_a,
        sci_result,
      );
      // v2
      let int_result = int_a.sqrt();
      let sci_result = sci_a.sqrt_truncate(Decimals(0));
      assert_eq!(
        Ok(Scientific::from(int_result)),
        sci_result,
        "function {}({}) -> {:?} = {:?}",
        "sqrt_v2",
        int_a,
        int_result,
        sci_result,
      );
      // v2.1
      let int_result = int_a.sqrt();
      let sci_result = sci_a
        .sqrt_rpsp(Decimals(0))
        .map(|s| s.truncate(Decimals(0)));
      assert_eq!(
        Ok(Scientific::from(int_result)),
        sci_result,
        "function {}({}) -> {:?} = {:?}",
        "sqrt_v2",
        int_a,
        int_result,
        sci_result,
      );
    }
  }
}
