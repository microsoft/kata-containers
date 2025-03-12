use core::str::FromStr;

pub(crate) fn parse_scientific(input: &str) -> Result<Option<(Vec<u8>, isize)>, ()> {
  // split at 'e'/'E', and parse second half as isize (defaults to 0)
  let mut input = input.split(|i| i == 'e' || i == 'E');
  let mantissa = input.next().ok_or(())?;
  let mut exponent = input
    .next()
    .map_or(Ok(0), isize::from_str)
    .map_err(|_| ())?;
  if input.next().is_some() {
    return Err(()); // there is more than one 'e'/'E'
  }

  // split mantissa at '.', the second half defaults to an empty slice
  let mut input = mantissa.as_bytes().split(|m| *m == b'.');
  let mantissa_pre = input.next().ok_or(())?;
  let mantissa_post = input.next().unwrap_or(&[]);
  if input.next().is_some() {
    return Err(()); // there is more than one '.'
  }

  // adapt exponent
  exponent -= mantissa_post.len() as isize;

  // create a vector for the mantissa and copy it
  let mut mantissa = Vec::with_capacity(mantissa_pre.len() + mantissa_post.len());
  let mut leading_zeroes = false;
  for (is_post, source) in [mantissa_pre, mantissa_post].into_iter().enumerate() {
    for m in source.iter().copied() {
      if m == b'_' {
        if is_post != 0 {
          // all post decimal dot digits are removed but some are spacers
          exponent += 1;
        }
        continue;
      } else if !m.is_ascii_digit() {
        return Err(());
      } else {
        let m = m & 0x0f;
        // do not copy leading zeroes
        if mantissa.is_empty() && m == 0 {
          leading_zeroes = true;
        } else {
          mantissa.push(m);
        }
      }
    }
  }
  // remove all trailing zeroes
  while mantissa.last() == Some(&0) {
    mantissa.pop();
    exponent += 1;
  }

  // fail if no mantissa is given
  if mantissa.is_empty() && !leading_zeroes {
    return Err(());
  }

  Ok(if mantissa.is_empty() {
    None
  } else {
    Some((mantissa, exponent))
  })
}

#[test]
fn test() {
  for (source, expected) in [
    // empty mantissa is an error
    ("", Err(())),
    // zero
    ("0", Ok(None)),
    ("00", Ok(None)),
    ("0.0", Ok(None)),
    ("0e7", Ok(None)),
    // single digit result
    ("6", Ok(Some((vec![6], 0)))),
    ("60", Ok(Some((vec![6], 1)))),
    ("060", Ok(Some((vec![6], 1)))),
    ("0.060", Ok(Some((vec![6], -2)))),
    // exponents
    ("6e1", Ok(Some((vec![6], 1)))),
    ("6e+1", Ok(Some((vec![6], 1)))),
    ("6e-1", Ok(Some((vec![6], -1)))),
    ("0.060e2", Ok(Some((vec![6], 0)))),
    ("0.050E-2", Ok(Some((vec![5], -4)))),
    // invalid numbers
    ("5e3e9", Err(())),
    ("5e3.9", Err(())),
    ("5.3.9", Err(())),
    ("x", Err(())),
    ("hello.world", Err(())),
    // spacer
    ("6_000", Ok(Some((vec![6], 3)))),
    ("70.06", Ok(Some((vec![7, 0, 0, 6], -2)))),
    ("8_0.0_6", Ok(Some((vec![8, 0, 0, 6], -2)))),
  ] {
    assert_eq!(
      parse_scientific(source),
      expected,
      "parsing of \"{}\"",
      source
    );
  }
}
