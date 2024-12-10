#[cfg(not(feature = "arc"))]
use alloc::rc::Rc;
#[cfg(feature = "arc")]
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(not(feature = "arc"))]
#[derive(Clone)]
pub(crate) enum Owner {
  None,
  Vec(Rc<Vec<u8>>),
}

#[cfg(feature = "arc")]
#[derive(Clone)]
pub(crate) enum Owner {
  None,
  Vec(Arc<Vec<u8>>),
}

impl Owner {
  #[cfg(not(feature = "arc"))]
  #[inline]
  pub(crate) fn new(data: Vec<u8>) -> Owner {
    Owner::Vec(Rc::new(data))
  }
  #[cfg(feature = "arc")]
  #[inline]
  pub(crate) fn new(data: Vec<u8>) -> Owner {
    Owner::Vec(Arc::new(data))
  }

  #[cfg(not(feature = "arc"))]
  #[inline]
  pub(crate) fn make_writeable(&mut self) -> Result<(), ()> {
    match self {
      Owner::None => Err(()),
      Owner::Vec(ref v) => {
        if Rc::strong_count(v) == 1 {
          Ok(())
        } else {
          Err(())
        }
      }
    }
  }

  #[cfg(feature = "arc")]
  #[inline]
  pub(crate) fn make_writeable(&mut self) -> Result<(), ()> {
    match core::mem::replace(self, Owner::None) {
      Owner::None => Err(()),
      Owner::Vec(v) => match Arc::try_unwrap(v) {
        Ok(v) => {
          *self = Owner::new(v);
          Ok(())
        }
        Err(s) => {
          *self = Owner::Vec(s);
          Err(())
        }
      },
    }
  }
}
