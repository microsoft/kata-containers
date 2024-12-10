use crate::types::owner::Owner;
use crate::types::precision::Precision;
use crate::types::ptr::Ptr;
use crate::types::rounding_mode::RoundingMode;
use crate::types::rounding_rpsp::RPSP;
use crate::types::sci::Sci;

impl Sci {
  pub(crate) fn round_assign(&mut self, precision: Precision, rounding: RoundingMode) {
    let len = self.precision_len(precision);
    if len < 0 {
      if let (RoundingMode::RPSP(RPSP), Precision::Decimals(d)) = (rounding, precision) {
        self.exponent = -d;
        self.assign_one();
      } else {
        self.assign_zero();
      }
    } else if len >= self.len {
      // more precision requested as available: just return the number
    } else if !rounding.round_away_from_zero(
      self.sign.is_negative(),
      if len == 0 { 0 } else { self.data[len - 1] },
      self.data[len],
      len + 1 == self.len,
    ) {
      // the rounding does result in no change
      self.truncate_assign(Precision::Digits(len));
    } else if len == 0 {
      // the new number should have 0 of the current digits but due to overflow one
      // is added in front
      self.exponent += self.len;
      self.assign_one();
    } else {
      // adapt length (and exponent)
      self.exponent += self.len - len;
      self.len = len;

      let mut ptr = make_writeable(self);
      ptr = ptr.offset(self.len - 1);

      while self.len > 0 && *ptr == 9 {
        self.len -= 1;
        self.exponent += 1;
        ptr.dec();
      }
      if self.len == 0 {
        // all digits where 9 and this is an overflow
        // replace mantissa with `1` and set exponent/len/owner accordingly
        self.assign_one();
      } else {
        *ptr += 1;
      }
    }
  }
}

/// either ensures that the data is no longer accessed or copy it
fn make_writeable(sci: &mut Sci) -> Ptr {
  match sci.owner.make_writeable() {
    Ok(()) => {
      // it is guaranteed that there is no other access to the data
      // and thus we can modify it
    }
    Err(()) => {
      // copy the data from the old to the new owner
      let mut vec = sci.data.as_slice(sci.len).to_vec();
      sci.data = Ptr::new_mut(vec.as_mut_slice());
      sci.owner = Owner::new(vec);
    }
  }

  sci.data // reminder: Ptr is Copy
}
