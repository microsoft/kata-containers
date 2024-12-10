//! Provides easy access to data from the `/proc/swaps` and `/proc/mounts` files.
//!
//! ```rust,no_run
//! extern crate proc_mounts;
//!
//! use proc_mounts::{MountIter, SwapIter};
//! use std::io;
//!
//! fn main() -> io::Result<()> {
//!     println!("# Active Mounts");
//!     for mount in MountIter::new()? {
//!         println!("{:#?}", mount);
//!     }
//!
//!     println!("# Active Swaps");
//!     for swap in SwapIter::new()? {
//!         println!("{:#?}", swap);
//!     }
//!
//!     Ok(())
//! }
//! ```

mod mounts;
mod swaps;

pub use self::{mounts::*, swaps::*};