use crate::types::rounding::Rounding;
use crate::types::rounding_rpsp::RPSP;

#[allow(clippy::upper_case_acronyms)]
pub(crate) enum RoundingMode {
  Rounding(Rounding),
  RPSP(RPSP),
}

impl RoundingMode {
  #[inline]
  pub(crate) fn round_away_from_zero(
    self,
    is_negative: bool,
    before: i8,
    after: i8,
    no_trailing_digits: bool,
  ) -> bool {
    match self {
      RoundingMode::Rounding(rounding) => {
        rounding.round_away_from_zero(is_negative, before, after, no_trailing_digits)
      }
      RoundingMode::RPSP(rpsp) => {
        rpsp.round_away_from_zero(is_negative, before, after, no_trailing_digits)
      }
    }
  }
}
