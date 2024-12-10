[![Codecov](https://codecov.io/github/alexkazik/scientific/coverage.svg?branch=main)](https://codecov.io/gh/alexkazik/scientific)
[![Dependency status](https://deps.rs/repo/github/alexkazik/scientific/status.svg)](https://deps.rs/repo/github/alexkazik/scientific)
[![crates.io](https://img.shields.io/crates/v/scientific.svg)](https://crates.io/crates/scientific)
[![Downloads](https://img.shields.io/crates/d/scientific.svg)](https://crates.io/crates/scientific)
[![Github stars](https://img.shields.io/github/stars/alexkazik/scientific.svg?logo=github)](https://github.com/alexkazik/scientific/stargazers)
[![License](https://img.shields.io/crates/l/scientific.svg)](./LICENSE)

# crate scientific

<!-- cargo-rdme start -->

Arbitrary precision scientific number

## Constants

Use [`Scientific!`](macro@crate::Scientific) to create constant numbers.

```rust
use scientific::Scientific;
let n1 = Scientific!(1e100);
let n2 = Scientific!(1e80);
assert_eq!(&n1 + &n2, Scientific!(1.00000000000000000001e100));
// An f64 has only a precision of about 15.9 digits, this are already 21.
```

## Invocation

All functions expect a reference to the [`Scientific`](struct@crate::Scientific) number. (See example above.)

## Conversion

There are `From` and `TryFrom` traits for conversion between [`Scientific`](struct@crate::Scientific) and integers, floats and strings.

Converting a scientific number with decimals to an integer will fail.

There is a `FromStr` instance (which clones the `str` and calls `Scientific::from_string`).

The functions `Scientific::to_bytes` and `Scientific::from_bytes` use a compressed representation and not ASCII
(this format will also be used when using serde with non human-readable formats).

## Precision

Most functions work in truly arbitrary precision, please be aware of this.

For example: adding 1e1000 and 1e-1000, which both have only one byte of mantissa, results in 2001 bytes of mantissa.

Functions for division and square root (which depends on div) as also all rounding functions require
a precision to be specified, the result is only calculated to that precision.

It can be specified as `Decimals` or `Digits`. When using decimals specify the number of decimal places to
calculate (`2` for `0.01` as the smallest number, `0` for `1` and `-2` for `100`). When using digits specify
the number of digits in the mantissa (using <= 0 digits will always result in zero).

Shortcuts: `Precision::INTEGER` for integer calculations (aka `Decimals(0)`) and `Precision::F64` for
calculations with a slightly better precision as an f64 (aka `Digits(16)`).

## Shifting

The shifting operators do shift by one digit (and not one bit as you may expected).

## Rounding

The functions `round`/`round_assign` support several rounding options. See `Rounding`.

The functions above should be only used for the final rounding. If rounding in between is required (e.g. to keep the mantissa manageable) use
`round_rpsp`/`round_assign` with at least the same precision than the final one.
The rounding will create one more digit than you required, to easily use it.
RPSP stands for Rounding to prepare for shorter precision, see [Wikipedia](https://en.wikipedia.org/wiki/Rounding#Rounding_to_prepare_for_shorter_precision) for more information.

In any case it's preferred to use the `*_assign` version since it can save reallocation of the mantissa (though not everytime relocation is required or can be avoided).

### Example

```rust
let precision = Precision::Digits(30); // precision for intermediate roundings and the final one
// do calculations
value.round_rpsp_assign(precision); // round to 31 digits with 'Rounding to prepare for shorter precision'
// do more calculations
value.round_assign(precision, RoundHalfUp); // round to 30 digits with the method 'RoundHalfUp'
```

## Truncating

The functions `truncate`/`truncate_assign` are identical to rounding with `RoundTowardsZero` but faster.

Also `truncate_assign` is faster than `truncate` because it does not need to clone.
Either way it does never require relocation of the mantissa (since it's not changed, just maybe referenced to a prefix of it).

## Features

- `serde`: Enable De-/Serialization with serde.

- `macro`: Re-export the [`Scientific!`](macro@crate::Scientific) macro, enabled by default.

- `std`: If activated the library requires `std` and the `Error` trait is implemented for all error types.
  Without it the library is `no_std`.

- `arc`: Use of `Arc` instead of `Rc`, which enables `Send` and `Sync` for [`Scientific`](struct@crate::Scientific).
  Though `Arc` is more expensive, but since it's only used during create/clone/drop of
  the [`Scientific`](struct@crate::Scientific) number it's probably not that much.

- `debug`: Enables several checks. Very helpful during development of this lib.

## Exponent

The exponent is represented as an `isize`. It is expected that it will never under-/overflow,
even when smaller numbers are added/subtracted, like e.g. the length of the mantissa.

This is not checked!

<!-- cargo-rdme end -->
