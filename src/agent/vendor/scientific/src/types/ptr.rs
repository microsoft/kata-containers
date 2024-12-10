use core::fmt::Write;
use core::ops::{Deref, DerefMut, Index, IndexMut, Range};
use core::ptr::{copy_nonoverlapping, NonNull};
use core::slice::from_raw_parts;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct Ptr {
  ptr: NonNull<u8>,
}

impl Ptr {
  #[inline]
  const fn new_ptr(ptr: *const u8) -> NonNull<u8> {
    unsafe { NonNull::new_unchecked(ptr.cast_mut()) }
  }

  #[inline]
  pub(crate) const fn new(slice: &[u8]) -> Ptr {
    Ptr {
      ptr: Self::new_ptr(slice.as_ptr()),
    }
  }

  #[inline]
  pub(crate) fn new_mut(slice: &mut [u8]) -> Ptr {
    Ptr {
      ptr: Self::new_ptr(slice.as_mut_ptr()),
    }
  }

  #[inline]
  pub(crate) const fn new_invalid() -> Ptr {
    Ptr {
      ptr: NonNull::dangling(),
    }
  }

  #[inline]
  pub(crate) fn offset(self, count: isize) -> Ptr {
    Ptr {
      ptr: Self::new_ptr(unsafe { self.ptr.as_ptr().offset(count) }),
    }
  }

  #[inline]
  pub(crate) fn copy_to_nonoverlapping(self, len: isize, to: Ptr, offset: isize) {
    unsafe {
      copy_nonoverlapping(
        self.ptr.as_ptr(),
        to.ptr.as_ptr().offset(offset),
        len as usize,
      );
    }
  }

  #[inline]
  pub(crate) fn as_slice(&self, len: isize) -> &[u8] {
    unsafe { from_raw_parts(self.ptr.as_ptr(), len as usize) }
  }

  #[inline]
  pub(crate) fn offset_from(self, other: Ptr) -> isize {
    unsafe { self.ptr.as_ptr().offset_from(other.ptr.as_ptr()) }
  }

  #[inline]
  pub(crate) fn inc(&mut self) {
    self.ptr = Self::new_ptr(unsafe { self.ptr.as_ptr().add(1) });
  }

  #[inline]
  pub(crate) fn dec(&mut self) {
    self.ptr = Self::new_ptr(unsafe { self.ptr.as_ptr().sub(1) });
  }

  #[inline]
  pub(crate) fn write_char<W: Write>(
    self,
    f: &mut W,
    offset: isize,
  ) -> Result<(), core::fmt::Error> {
    f.write_char((b'0' + (self[offset] as u8)).into())
  }

  #[inline]
  pub(crate) fn write_chars<W: Write>(
    self,
    f: &mut W,
    range: Range<isize>,
  ) -> Result<(), core::fmt::Error> {
    for i in range {
      f.write_char((b'0' + (self[i] as u8)).into())?;
    }
    Ok(())
  }
}

impl Index<isize> for Ptr {
  type Output = i8;

  #[inline]
  fn index(&self, index: isize) -> &Self::Output {
    unsafe { &*self.ptr.as_ptr().cast::<i8>().offset(index) }
  }
}

impl IndexMut<isize> for Ptr {
  #[inline]
  fn index_mut(&mut self, index: isize) -> &mut Self::Output {
    unsafe { &mut *self.ptr.as_ptr().cast::<i8>().offset(index) }
  }
}

impl Deref for Ptr {
  type Target = i8;

  #[inline]
  fn deref(&self) -> &Self::Target {
    self.index(0)
  }
}

impl DerefMut for Ptr {
  #[inline]
  fn deref_mut(&mut self) -> &mut Self::Target {
    self.index_mut(0)
  }
}
