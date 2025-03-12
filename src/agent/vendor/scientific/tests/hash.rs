use scientific::Scientific;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

#[test]
fn hash() {
  let numbers = [
    Scientific::from_str("0").unwrap(),
    Scientific::from_str("1").unwrap(),
    Scientific::from_str("100").unwrap(),
    Scientific::from_str("1e2").unwrap(),
  ];

  for a in &numbers {
    for b in &numbers {
      if a == b {
        assert_eq!(hash_one(&a), hash_one(&b));
      }
    }
  }
}

fn hash_one<T: Hash>(x: &T) -> u64 {
  let mut hasher = DefaultHasher::new();
  x.hash(&mut hasher);
  hasher.finish()
}
