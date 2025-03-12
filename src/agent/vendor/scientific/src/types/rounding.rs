use core::cmp::Ordering;
use core::hint::unreachable_unchecked;

/// Enum to implement different rounding methods.
///
/// Method                    | Result is -2  | Result is -1  | Result is 0  | Result is 1 | Result is 2 | Implementor
/// ------------------------- | :-----------: | :-----------: | :----------: | :---------: | :---------: | ------------------
/// Directed, Down            | \[-2.0, -1.0) | \[-1.0,  0.0) |  \[0.0, 1.0) | \[1.0, 2.0) | \[2.0, 3.0) | [`RoundDown`](Rounding::RoundDown)
/// Directed, Up              |  (-3.0, -2.0] |  (-2.0, -1.0] |  (-1.0, 0.0] |  (0.0, 1.0] |  (1.0, 2.0] | [`RoundUp`](Rounding::RoundUp)
/// Directed, Towards 0       |  (-3.0, -2.0] |  (-2.0, -1.0] |  (-1.0, 1.0) | \[1.0, 2.0) | \[2.0, 3.0) | [`RoundTowardsZero`](Rounding::RoundTowardsZero)
/// Directed, Away From 0     | \[-2.0, -1.0) | \[-1.0,  0.0) |      0.0     |  (0.0, 1.0] |  (1.0, 2.0] | [`RoundAwayFromZero`](Rounding::RoundAwayFromZero)
/// Nearest, Half Down        |  (-2.5, -1.5] |  (-1.5, -0.5] |  (-0.5, 0.5] |  (0.5, 1.5] |  (1.5, 2.5] | [`RoundHalfDown`](Rounding::RoundHalfDown)
/// Nearest, Half Up          | \[-2.5, -1.5) | \[-1.5, -0.5) | \[-0.5, 0.5) | \[0.5, 1.5) | \[1.5, 2.5) | [`RoundHalfUp`](Rounding::RoundHalfUp)
/// Nearest, Half Towards 0   | \[-2.5, -1.5) | \[-1.5, -0.5) | \[-0.5, 0.5] |  (0.5, 1.5] |  (1.5, 2.5] | [`RoundHalfTowardsZero`](Rounding::RoundHalfTowardsZero)
/// Nearest, Half Away From 0 |  (-2.5, -1.5] |  (-1.5, -0.5] |  (-0.5, 0.5) | \[0.5, 1.5) | \[1.5, 2.5) | [`RoundHalfAwayFromZero`](Rounding::RoundHalfAwayFromZero)
/// Nearest, Half To Even     | \[-2.5, -1.5] |  (-1.5, -0.5) | \[-0.5, 0.5] |  (0.5, 1.5) | \[1.5, 2.5] | [`RoundHalfToEven`](Rounding::RoundHalfToEven)
/// Nearest, half To Odd      |  (-2.5, -1.5) | \[-1.5, -0.5] |  (-0.5, 0.5) | \[0.5, 1.5] |  (1.5, 2.5) | [`RoundHalfToOdd`](Rounding::RoundHalfToOdd)
#[derive(Copy, Clone, Debug, Default)]
#[non_exhaustive]
#[cfg_attr(no_re_export, allow(dead_code))]
pub enum Rounding {
  /// Also known as floor.
  RoundDown,
  /// Also known as ceiling.
  RoundUp,
  /// Also known as truncate.
  RoundTowardsZero,
  /// Used by [`f64::round`].
  RoundAwayFromZero,
  ///
  RoundHalfDown,
  ///
  RoundHalfUp,
  ///
  RoundHalfTowardsZero,
  #[default]
  /// \[Default] Probably what you learned in school.
  RoundHalfAwayFromZero,
  /// Often used in binary IEEE Floating-Point arithmetic.
  ///
  /// Not for the rounding operation but by other operations, which create more digits as can be stored.
  RoundHalfToEven,
  ///
  RoundHalfToOdd,
}

impl Rounding {
  #[inline]
  pub(crate) fn round_away_from_zero(
    self,
    is_negative: bool,
    before: i8,
    after: i8,
    no_trailing_digits: bool,
  ) -> bool {
    match self {
      Rounding::RoundDown
      | Rounding::RoundUp
      | Rounding::RoundTowardsZero
      | Rounding::RoundAwayFromZero => {
        if after == 0 && no_trailing_digits {
          false
        } else {
          match self {
            Rounding::RoundDown => is_negative,
            Rounding::RoundUp => !is_negative,
            Rounding::RoundTowardsZero => false,
            Rounding::RoundAwayFromZero => true,
            _ => unsafe { unreachable_unchecked() },
          }
        }
      }
      Rounding::RoundHalfDown
      | Rounding::RoundHalfUp
      | Rounding::RoundHalfTowardsZero
      | Rounding::RoundHalfAwayFromZero
      | Rounding::RoundHalfToEven
      | Rounding::RoundHalfToOdd => {
        match after.cmp(&5).then_with(|| {
          if no_trailing_digits {
            Ordering::Equal
          } else {
            Ordering::Greater
          }
        }) {
          Ordering::Less => false,
          Ordering::Equal => match self {
            Rounding::RoundHalfDown => is_negative,
            Rounding::RoundHalfUp => !is_negative,
            Rounding::RoundHalfTowardsZero => false,
            Rounding::RoundHalfAwayFromZero => true,
            Rounding::RoundHalfToEven => before & 1 != 0,
            Rounding::RoundHalfToOdd => before & 1 == 0,
            _ => unsafe { unreachable_unchecked() },
          },
          Ordering::Greater => true,
        }
      }
    }
  }
}
