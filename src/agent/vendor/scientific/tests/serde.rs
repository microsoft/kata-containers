#![cfg(feature = "serde")]

use scientific::Scientific;
use std::str::FromStr;

#[test]
fn serde() {
  for (sci, json, postcard) in &[
    (
      Scientific::from_str("-12340").unwrap(),
      r#""-12340""#,
      vec![3, 129, 30, 208],
    ),
    (
      Scientific::from_str("1.234").unwrap(),
      r#""1.234""#,
      vec![3, 125, 30, 208],
    ),
    (
      Scientific::from_str("123.4e9").unwrap(),
      r#""1.234e11""#,
      vec![3, 8, 30, 208],
    ),
    (
      Scientific::from_str("123.4e99").unwrap(),
      r#""1.234e101""#,
      vec![4, 60, 98, 30, 208],
    ),
    (
      Scientific::from_str("123.4e999").unwrap(),
      r#""1.234e1001""#,
      vec![5, 61, 3, 230, 30, 208],
    ),
  ] {
    assert_eq!(
      serde_json::to_string(sci).map_err(|_| ()),
      Ok(json.to_string()),
      "{sci} to json"
    );
    assert_eq!(
      serde_json::from_str(json).map_err(|_| ()),
      Ok(sci.clone()),
      "{sci} from json"
    );
    assert_eq!(
      postcard::to_extend(sci, Vec::new()),
      Ok(postcard.clone()),
      "{sci} to postcard"
    );
    assert_eq!(
      postcard::from_bytes(postcard),
      Ok(sci.clone()),
      "{sci} from postcard"
    );
  }
}
