use crate::types::owner::Owner;
use crate::types::ptr::Ptr;
use crate::types::sci::Sci;
use crate::types::sign::Sign;

pub(crate) struct Builder(Sci);

impl Builder {
  pub(crate) fn new(sign: Sign, len: isize, exponent: isize) -> (Builder, Ptr) {
    #[cfg(feature = "debug")]
    assert!(len > 0);

    let mut vec = vec![0; len as usize];
    let data = Ptr::new_mut(vec.as_mut_slice());
    (
      Builder(Sci {
        sign,
        data,
        len,
        exponent,
        owner: Owner::new(vec),
      }),
      data,
    )
  }

  #[inline]
  pub(crate) fn from_data(sign: Sign, data: Ptr, len: isize, exponent: isize, owner: Owner) -> Sci {
    Builder(Sci {
      sign,
      data,
      len,
      exponent,
      owner,
    })
    .finish()
  }

  #[inline]
  pub(crate) fn finish(mut self) -> Sci {
    b_mut_trim_zeroes(&mut self.0);
    self.0
  }
}

fn b_mut_trim_zeroes(value: &mut Sci) {
  // remove leading zeroes
  while value.len > 0 && *value.data == 0 {
    value.data.inc();
    value.len -= 1;
  }

  // remove trailing zeroes
  while value.len > 0 && value.data[value.len - 1] == 0 {
    value.len -= 1;
    value.exponent += 1;
  }

  if value.len <= 0 {
    // if nothing remains -> set to zero
    value.assign_zero();
  }
}
