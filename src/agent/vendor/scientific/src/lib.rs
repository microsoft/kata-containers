#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![allow(rustdoc::redundant_explicit_links)]
// enable pedantic group but not all
#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::if_not_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::single_match_else)]

//! Arbitrary precision scientific number
//!
//! # Constants
//!
//! Use [`Scientific!`](macro@crate::Scientific) to create constant numbers.
//!
//! ```
//! use scientific::Scientific;
//! let n1 = Scientific!(1e100);
//! let n2 = Scientific!(1e80);
//! assert_eq!(&n1 + &n2, Scientific!(1.00000000000000000001e100));
//! // An f64 has only a precision of about 15.9 digits, this are already 21.
//! ```
//!
//! # Invocation
//!
//! All functions expect a reference to the [`Scientific`](struct@crate::Scientific) number. (See example above.)
//!
//! # Conversion
//!
//! There are `From` and `TryFrom` traits for conversion between [`Scientific`](struct@crate::Scientific) and integers, floats and strings.
//!
//! Converting a scientific number with decimals to an integer will fail.
//!
//! There is a `FromStr` instance (which clones the `str` and calls [`Scientific::from_string`](crate::Scientific::from_string)).
//!
//! The functions [`Scientific::to_bytes`](crate::Scientific::to_bytes) and [`Scientific::from_bytes`](crate::Scientific::from_bytes) use a compressed representation and not ASCII
//! (this format will also be used when using serde with non human-readable formats).
//!
//! # Precision
//!
//! Most functions work in truly arbitrary precision, please be aware of this.
//!
//! For example: adding 1e1000 and 1e-1000, which both have only one byte of mantissa, results in 2001 bytes of mantissa.
//!
//! Functions for division and square root (which depends on div) as also all rounding functions require
//! a precision to be specified, the result is only calculated to that precision.
//!
//! It can be specified as [`Decimals`](crate::Decimals) or [`Digits`](crate::Digits). When using decimals specify the number of decimal places to
//! calculate (`2` for `0.01` as the smallest number, `0` for `1` and `-2` for `100`). When using digits specify
//! the number of digits in the mantissa (using <= 0 digits will always result in zero).
//!
//! Shortcuts: [`Precision::INTEGER`](crate::Precision::INTEGER) for integer calculations (aka `Decimals(0)`) and [`Precision::F64`](crate::Precision::F64) for
//! calculations with a slightly better precision as an f64 (aka `Digits(16)`).
//!
//! # Shifting
//!
//! The shifting operators do shift by one digit (and not one bit as you may expected).
//!
//! # Rounding
//!
//! The functions [`round`](crate::Scientific::round)/[`round_assign`](crate::Scientific::round_assign) support several rounding options. See [`Rounding`](crate::Rounding).
//!
//! The functions above should be only used for the final rounding. If rounding in between is required (e.g. to keep the mantissa manageable) use
//! [`round_rpsp`](crate::Scientific::round_rpsp)/[`round_assign`](crate::Scientific::round_rpsp_assign) with at least the same precision than the final one.
//! The rounding will create one more digit than you required, to easily use it.
//! RPSP stands for Rounding to prepare for shorter precision, see [Wikipedia](https://en.wikipedia.org/wiki/Rounding#Rounding_to_prepare_for_shorter_precision) for more information.
//!
//! In any case it's preferred to use the `*_assign` version since it can save reallocation of the mantissa (though not everytime relocation is required or can be avoided).
//!
//! ## Example
//!
//! ```
//! # use scientific::{Precision, RoundHalfUp, Scientific};
//! # let mut value = Scientific::ZERO;
//! let precision = Precision::Digits(30); // precision for intermediate roundings and the final one
//! // do calculations
//! value.round_rpsp_assign(precision); // round to 31 digits with 'Rounding to prepare for shorter precision'
//! // do more calculations
//! value.round_assign(precision, RoundHalfUp); // round to 30 digits with the method 'RoundHalfUp'
//! ```
//!
//! # Truncating
//!
//! The functions [`truncate`](crate::Scientific::truncate)/[`truncate_assign`](crate::Scientific::truncate_assign) are identical to rounding with [`RoundTowardsZero`](crate::Rounding::RoundTowardsZero) but faster.
//!
//! Also [`truncate_assign`](crate::Scientific::truncate_assign) is faster than [`truncate`](crate::Scientific::truncate) because it does not need to clone.
//! Either way it does never require relocation of the mantissa (since it's not changed, just maybe referenced to a prefix of it).
//!
//! # Features
//!
//! - `serde`: Enable De-/Serialization with serde.
//!
//! - `macro`: Re-export the [`Scientific!`](macro@crate::Scientific) macro, enabled by default.
//!
//! - `std`: If activated the library requires `std` and the [`Error`](::std::error::Error) trait is implemented for all error types.
//!   Without it the library is `no_std`.
//!
//! - `arc`: Use of [`Arc`](::alloc::sync::Arc) instead of [`Rc`](::alloc::rc::Rc), which enables [`Send`](::core::marker::Send) and [`Sync`](::core::marker::Sync) for [`Scientific`](struct@crate::Scientific).
//!   Though [`Arc`](::alloc::sync::Arc) is more expensive, but since it's only used during create/clone/drop of
//!   the [`Scientific`](struct@crate::Scientific) number it's probably not that much.
//!
//! - `debug`: Enables several checks. Very helpful during development of this lib.
//!
//! # Exponent
//!
//! The exponent is represented as an [`isize`](::core::isize). It is expected that it will never under-/overflow,
//! even when smaller numbers are added/subtracted, like e.g. the length of the mantissa.
//!
//! This is not checked!

#[macro_use]
extern crate alloc;

#[cfg(not(no_re_export))]
pub use crate::types::conversion_error::ConversionError;
#[cfg(not(no_re_export))]
pub use crate::types::error::Error;
#[cfg(not(no_re_export))]
pub use crate::types::precision::Precision::{self, Decimals, Digits};
#[cfg(not(no_re_export))]
pub use crate::types::rounding::Rounding::{
  self, RoundAwayFromZero, RoundDown, RoundHalfAwayFromZero, RoundHalfDown, RoundHalfToEven,
  RoundHalfToOdd, RoundHalfTowardsZero, RoundHalfUp, RoundUp,
};
#[cfg(not(no_re_export))]
pub use crate::types::scientific::Scientific;
#[cfg_attr(docsrs, doc(cfg(feature = "macro")))]
#[cfg(all(not(no_re_export), feature = "macro"))]
pub use scientific_macro::Scientific;

pub(crate) mod conversion;
pub(crate) mod math;
pub(crate) mod types;
