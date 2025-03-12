use crate::types::conversion_error::ConversionError;
use crate::types::owner::Owner;
use crate::types::ptr::Ptr;
use crate::types::sci::Sci;
use crate::types::sign::Sign;
use alloc::vec::Vec;
use core::convert::TryInto;

impl Sci {
  #[allow(clippy::too_many_lines)]
  pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Sci, ConversionError> {
    if bytes.is_empty() {
      return Ok(Sci::ZERO);
    }

    let prefix = bytes[0];
    let is_negative = prefix & 0x80 != 0;
    let prefix = prefix & 0x7f;
    let exponent;
    let pos;

    if prefix < 0x3c {
      exponent = prefix as isize;
      pos = 1;
    } else if prefix >= 0x40 {
      exponent = ((prefix | 0x80) as i8) as isize;
      pos = 1;
    } else if prefix == 0x3c {
      if bytes.len() < 1 + 1 {
        return Err(ConversionError::ParseError);
      }
      exponent = (bytes[1] as i8) as isize;
      pos = 1 + 1;
    } else if prefix == 0x3d {
      if bytes.len() < 1 + 2 {
        return Err(ConversionError::ParseError);
      }
      exponent = i16::from_be_bytes(bytes[1..=2].try_into().unwrap()) as isize;
      pos = 1 + 2;
    } else {
      #[cfg(target_pointer_width = "16")]
      return Err(ConversionError::ExponentTooLargeForThisPlatform);

      #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
      if prefix == 0x3e {
        if bytes.len() < 1 + 4 {
          return Err(ConversionError::ParseError);
        }
        exponent = i32::from_be_bytes(bytes[1..=4].try_into().unwrap()) as isize;
        pos = 1 + 4;
      } else {
        #[cfg(target_pointer_width = "32")]
        return Err(ConversionError::ExponentTooLargeForThisPlatform);

        #[cfg(target_pointer_width = "64")]
        {
          if bytes.len() < 1 + 8 {
            return Err(ConversionError::ParseError);
          }
          exponent = i64::from_be_bytes(bytes[1..=8].try_into().unwrap()) as isize;
          pos = 1 + 8;
        }
      }

      #[cfg(not(any(
        target_pointer_width = "16",
        target_pointer_width = "32",
        target_pointer_width = "64"
      )))]
      compile_error!("This target_pointer_width is not yet supported, please open a issue.")
    }

    let mut owned = Vec::with_capacity(((bytes.len() - pos + 11) * 12) / 5);
    let mut buf = 0;
    let mut buf_len = 0;
    let mut it = bytes[pos..].iter();
    '_loop: loop {
      while buf_len < 10 {
        match it.next() {
          None => break '_loop,
          Some(&v) => {
            buf = (buf << 8) | u16::from(v);
            buf_len += 8;
          }
        }
      }
      buf_len -= 10;
      let v = (buf >> buf_len) & 1023;
      if v >= 1000 {
        return Err(ConversionError::ParseError);
      }
      owned.push((v / 100) as u8);
      owned.push(((v / 10) % 10) as u8);
      owned.push((v % 10) as u8);
    }
    while buf_len >= 4 {
      buf_len -= 4;
      let v = (buf >> buf_len) & 15;
      if v > 10 {
        return Err(ConversionError::ParseError);
      }
      owned.push(v as u8);
    }
    if buf_len > 0 && buf << (16 - buf_len) != 0 {
      return Err(ConversionError::ParseError);
    }
    let mut len = owned.len() as isize;
    let data = Ptr::new(owned.as_slice());
    let mut trailing_zeroes = 0;
    while len > 0 && data[len - 1] == 0 {
      len -= 1;
      trailing_zeroes += 1;
    }
    if len == 0 || *data == 0 || trailing_zeroes != calculate_trailing_zeroes(len) {
      Err(ConversionError::ParseError)
    } else {
      Ok(Sci {
        sign: Sign::new(is_negative),
        data,
        len,
        exponent,
        owner: Owner::new(owned),
      })
    }
  }
}

#[inline]
fn calculate_trailing_zeroes(len: isize) -> isize {
  // Read in bytes_ser in the section "what to do with the remaining digits?"
  // how it's handled on serialization. This is a shortcut to all the required information.
  const TRAILING_ZEROES: u32 =
      // (0 << 0) |  dig=0, buf=0
      (1 << 2) | //  dig=0, buf=2
      (1 << 4) | //  dig=0, buf=4
      // (0 << 6) |  dig=0, buf=6
      (1 << 8) | //  dig=1, buf=0
      // (0 << 10) | dig=1, buf=2
      // (0 << 12) | dig=1, buf=4
      (2 << 14) | // dig=1, buf=6
      // (0 << 16) | dig=2, buf=0
      (2 << 18) | // dig=2, buf=2
      (1 << 20) | // dig=2, buf=4
      (1 << 22)  //  dig=2, buf=6
    ;
  let dig = len % 3;
  let buf = ((len / 3) * 10) % 8;
  ((TRAILING_ZEROES >> (dig * 8 + buf)) & 3) as isize
}
