// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{mem::size_of, slice, str};

use nix::libc::c_char;

/// The smallest number divisible by `align_to` and at least `num`.
/// Precondition: `align_to` is a power of 2.
/// Precondition: `num` + `align_to` < usize::MAX + 1.
#[inline]
pub fn align_to(num: usize, align_to: usize) -> usize {
    let agn = align_to - 1;

    (num + agn) & !agn
}

/// Convert from a &[c_char] to a &[u8].
pub fn byte_slice_from_c_str(c_str: &[c_char]) -> &[u8] {
    unsafe { slice::from_raw_parts(c_str as *const _ as *const u8, c_str.len()) }
}

/// Return a String parsed from the C string up to the first \0, or None
pub fn str_from_c_str(slc: &[c_char]) -> Option<&str> {
    let slc = byte_slice_from_c_str(slc);
    str_from_byte_slice(slc)
}

/// Return a String parsed from the byte slice up to the first \0, or None
pub fn str_from_byte_slice(slc: &[u8]) -> Option<&str> {
    slc.iter()
        .position(|c| *c == b'\0')
        .and_then(|i| str::from_utf8(&slc[..i]).ok())
}

/// Return a mutable slice from the mutable C string provided as input
pub fn mut_slice_from_c_str(c_str: &mut [c_char]) -> &mut [u8] {
    unsafe { slice::from_raw_parts_mut(c_str as *mut _ as *mut u8, c_str.len()) }
}

/// Convert the C struct into a properly-sized byte slice
pub fn slice_from_c_struct<T>(strct: &T) -> &[u8] {
    unsafe { slice::from_raw_parts(strct as *const _ as *const u8, size_of::<T>()) }
}

/// Convert the byte slice into a properly sized C string reference
pub fn c_struct_from_slice<T>(slice: &[u8]) -> Option<&T> {
    unsafe { (slice as *const _ as *const T).as_ref() }
}
