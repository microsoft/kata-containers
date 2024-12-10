use scientific::{ConversionError, Scientific};
use std::str::FromStr;

#[test]
fn conversion_error() {
  // FloatIsNotFinite
  assert_eq!(
    Scientific::try_from(f32::NAN),
    Err(ConversionError::FloatIsNotFinite)
  );
  assert_eq!(
    Scientific::try_from(f32::INFINITY),
    Err(ConversionError::FloatIsNotFinite)
  );
  assert_eq!(
    Scientific::try_from(f64::NEG_INFINITY),
    Err(ConversionError::FloatIsNotFinite)
  );
  assert_eq!(
    Scientific::try_from(f64::NAN),
    Err(ConversionError::FloatIsNotFinite)
  );
  assert_eq!(
    Scientific::try_from(f64::INFINITY),
    Err(ConversionError::FloatIsNotFinite)
  );
  assert_eq!(
    Scientific::try_from(f64::NEG_INFINITY),
    Err(ConversionError::FloatIsNotFinite)
  );

  // NumberTooLarge
  assert_eq!(
    i8::try_from(&Scientific::from_str("500").unwrap()),
    Err(ConversionError::NumberTooLarge)
  );
  assert_eq!(
    i8::try_from(&Scientific::from_str("-500").unwrap()),
    Err(ConversionError::NumberTooLarge)
  );
  // NumberTooLarge
  assert_eq!(
    u8::try_from(&Scientific::from_str("500").unwrap()),
    Err(ConversionError::NumberTooLarge)
  );

  // ParseError
  assert_eq!(
    Scientific::from_raw_parts(false, vec![15], 0),
    Err(ConversionError::ParseError)
  );
  assert_eq!(Scientific::from_str(""), Err(ConversionError::ParseError));
  assert_eq!(Scientific::from_str("-"), Err(ConversionError::ParseError));
  assert_eq!(Scientific::from_str("@"), Err(ConversionError::ParseError));
  assert_eq!(Scientific::from_str("5@"), Err(ConversionError::ParseError));
  assert_eq!(Scientific::from_str("5e"), Err(ConversionError::ParseError));
  assert_eq!(
    Scientific::from_str("5e@"),
    Err(ConversionError::ParseError)
  );
  assert_eq!(Scientific::from_str("."), Err(ConversionError::ParseError));

  // NumberIsNegative
  assert_eq!(
    u8::try_from(&Scientific::from_str("-50").unwrap()),
    Err(ConversionError::NumberIsNegative)
  );

  // NumberIsNegative
  assert_eq!(
    u8::try_from(&Scientific::from_str("55.55").unwrap()),
    Err(ConversionError::NumberIsNotAnInteger)
  );
  assert_eq!(
    i8::try_from(&Scientific::from_str("55.55").unwrap()),
    Err(ConversionError::NumberIsNotAnInteger)
  );

  // deserialization error
  for bytes in [
    vec![0x3c],
    vec![0x3d],
    vec![0x3d, 0x00],
    vec![0x3e],
    vec![0x3f],
    vec![0x00, 0xff, 0xc0], // value "1023" (3 digits), "0" (1 digit), 0b00 padding
    vec![0x00, 0xff],       // value "15" (1 digit), "15" (1 digit)
    vec![0x00, 0x1e, 0xc1], // value "123" (3 digits), "0" (1 digit), 0b01 padding
    vec![0x00],             // len==0
    vec![0x00, 0x18, 0xc0], // *data==0: value "099" (3 digits), "0" (1 digit), 0b00 padding
    vec![0x00, 0x7d, 0x00], // trailing zeroes: value "500" (3 digits), "0" (1 digit), 0b00 padding
  ] {
    assert_eq!(
      Scientific::from_bytes(&bytes),
      Err(ConversionError::ParseError)
    );
  }

  // text
  assert_eq!(
    &ConversionError::FloatIsNotFinite.to_string(),
    "Float is not finite"
  );
  assert_eq!(
    &ConversionError::NumberTooLarge.to_string(),
    "Number too large"
  );
  assert_eq!(&ConversionError::ParseError.to_string(), "Parse error");
  assert_eq!(
    &ConversionError::NumberIsNegative.to_string(),
    "Number is negative"
  );
  assert_eq!(
    &ConversionError::NumberIsNotAnInteger.to_string(),
    "Number is not an integer"
  );
  assert_eq!(
    &ConversionError::ExponentTooLargeForThisPlatform.to_string(),
    "Exponent is too large for this platform"
  );
}
