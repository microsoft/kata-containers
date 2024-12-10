#[allow(clippy::upper_case_acronyms)]
pub(crate) struct RPSP;

impl RPSP {
  #[inline]
  #[allow(clippy::unused_self)]
  pub(crate) fn round_away_from_zero(
    self,
    _is_negative: bool,
    before: i8,
    _after: i8,
    _no_trailing_digits: bool,
  ) -> bool {
    // the check usually would be `(before == 0 || before == 5) && !(after == 0 && no_trailing_digits)`
    // but if after is 0 and there are no trailing digits then the those are trailing zeroes and
    // they would automatically removed and thus there is no reason to round.
    before == 0 || before == 5
  }
}
