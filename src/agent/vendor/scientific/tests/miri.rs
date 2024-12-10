use crate::float_common::test_float;
use crate::integer_common::test_integer;

mod float_common;
mod integer_common;

#[test]
fn miri() {
  test_float([-4.33333333, 0., 1., 3., 7.5].into_iter(), &[0, 2], false);
  test_integer([-4, 0, 1, 3, 7].into_iter(), 3, false);
}
