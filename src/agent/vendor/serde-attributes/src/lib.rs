//! Serde Attributes. [Extract from](https://github.com/serde-rs/serde/blob/v1.0.127/serde_derive/src/internals/attr.rs#L290)
//!
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "attr-alias")]
pub mod alias;
#[cfg(feature = "attr-alias")]
pub use alias::Alias;

#[cfg(feature = "attr-rename")]
pub mod rename;
#[cfg(feature = "attr-rename")]
pub use rename::{Rename, RenameIndependent};

#[cfg(feature = "attr-rename-all")]
pub mod rename_all;
#[cfg(feature = "attr-rename-all")]
pub use rename_all::{RenameAll, RenameAllIndependent};

/// [Ref](https://github.com/serde-rs/serde/blob/v1.0.127/serde_derive/src/internals/symbol.rs#L26)
#[cfg(any(feature = "attr-rename", feature = "attr-rename-all"))]
#[cfg(feature = "with-syn")]
pub const SERIALIZE: &str = "serialize";
#[cfg(any(feature = "attr-rename", feature = "attr-rename-all"))]
#[cfg(feature = "with-syn")]
/// [Ref](https://github.com/serde-rs/serde/blob/v1.0.127/serde_derive/src/internals/symbol.rs#L14)
pub const DESERIALIZE: &str = "deserialize";
