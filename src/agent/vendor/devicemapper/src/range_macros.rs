// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// An omnibus macro that includes all simple macros.
macro_rules! range_u64 {
    ( $(#[$comment:meta])? $T: ident, $display_name: expr) => {
        range!($(#[$comment])? $T, $display_name, u64, serialize_u64);
        from_u64!($T);
        mul!($T, u64, u32, u16, u8);
        div!($T, u64, u32, u16, u8);
    }
}

macro_rules! range_u128 {
    ( $(#[$comment:meta])? $T: ident, $display_name: expr) => {
        range!($(#[$comment])? $T, $display_name, u128, serialize_u128);
        from_u128!($T);
        mul!($T, u128, u64, u32, u16, u8);
        div!($T, u128, u64, u32, u16, u8);
    }
}

macro_rules! range {
    ( $(#[$comment:meta])? $T: ident, $display_name: expr, $inner:ty, $serde_method:ident) => {
        $(
            #[$comment]
        )?
        #[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $T(pub $inner);

        checked_add!($T);
        debug_macro!($T);
        display!($T, $display_name);
        serde_macro!($T, $serde_method);
        sum!($T);
        add!($T);
        add_assign!($T);
        sub!($T);
        sub_assign!($T);
        rem!($T);
        deref!($T, $inner);
    };
}

macro_rules! add {
    ($T:ident) => {
        impl std::ops::Add<$T> for $T {
            type Output = $T;
            fn add(self, rhs: $T) -> $T {
                $T(self.0 + *rhs)
            }
        }
    };
}

macro_rules! sub {
    ($T:ident) => {
        impl std::ops::Sub<$T> for $T {
            type Output = $T;
            fn sub(self, rhs: $T) -> $T {
                $T(self.0 - *rhs)
            }
        }
    };
}

macro_rules! add_assign {
    ($T:ident) => {
        impl std::ops::AddAssign<$T> for $T {
            fn add_assign(&mut self, rhs: $T) {
                *self = $T(self.0 + *rhs)
            }
        }
    };
}

macro_rules! sub_assign {
    ($T:ident) => {
        impl std::ops::SubAssign<$T> for $T {
            fn sub_assign(&mut self, rhs: $T) {
                *self = $T(self.0 - *rhs)
            }
        }
    };
}

macro_rules! deref {
    ($T:ident, $inner:ty) => {
        impl std::ops::Deref for $T {
            type Target = $inner;
            fn deref(&self) -> &$inner {
                &self.0
            }
        }
    };
}

macro_rules! from {
    ($T:ident, $inner:ty, $($t:ty),+) => {
        $(
            impl From<$t> for $T {
                fn from(t: $t) -> $T {
                    $T(<$inner>::from(t))
                }
            }
        )+

        impl From<usize> for $T {
            fn from(t: usize) -> $T {
                $T(t as $inner)
            }
        }

        impl From<$inner> for $T {
            fn from(t: $inner) -> $T {
                $T(t)
            }
        }
    };
}

macro_rules! from_u64 {
    ($T:ident) => {
        from!($T, u64, u32, u16, u8);
    };
}

macro_rules! from_u128 {
    ($T:ident) => {
        from!($T, u128, u64, u32, u16, u8);
    };
}

macro_rules! debug_macro {
    ($T:ident) => {
        impl std::fmt::Debug for $T {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, stringify!($T))?;
                write!(f, "({})", **self)
            }
        }
    };
}

macro_rules! display {
    ($T:ident, $display_name:expr) => {
        impl std::fmt::Display for $T {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{} {}", self.0, $display_name)
            }
        }
    };
}

macro_rules! serde_macro {
    ($T:ident, $serde_method:ident) => {
        impl serde::Serialize for $T {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.$serde_method(**self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $T {
            fn deserialize<D>(deserializer: D) -> Result<$T, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                Ok($T(serde::Deserialize::deserialize(deserializer)?))
            }
        }
    };
}

macro_rules! sum {
    ($T:ident) => {
        impl std::iter::Sum for $T {
            fn sum<I: Iterator<Item = $T>>(iter: I) -> $T {
                iter.fold($T::default(), std::ops::Add::add)
            }
        }
    };
}

// Define a complete set of division operations.
macro_rules! div {
    ($T:ident, $inner:ty, $($t:ty),+) => {
        $(
            impl std::ops::Div<$t> for $T {
                type Output = $T;
                fn div(self, rhs: $t) -> $T {
                    $T(self.0 / <$inner>::from(rhs))
                }
            }
        )+

        impl std::ops::Div<usize> for $T {
            type Output = $T;
            fn div(self, rhs: usize) -> $T {
                $T(self.0 / rhs as $inner)
            }
        }

        impl std::ops::Div<$inner> for $T {
            type Output = $T;
            fn div(self, rhs: $inner) -> $T {
                $T(self.0 / rhs)
            }
        }

        impl std::ops::Div for $T {
            type Output = $inner;
            fn div(self, rhs: $T) -> $inner {
                self.0 / *rhs
            }
        }
    };
}

// Define a complete set of multiplication operations.
macro_rules! mul {
    ($T:ident, $inner:ty, $($t:ty),+) => {
        $(
            impl std::ops::Mul<$t> for $T {
                type Output = $T;
                fn mul(self, rhs: $t) -> $T {
                    $T(self.0 * <$inner>::from(rhs))
                }
            }

            impl std::ops::Mul<$T> for $t {
                type Output = $T;
                fn mul(self, rhs: $T) -> $T {
                    $T(rhs.0 * <$inner>::from(self))
                }
            }
        )+

        impl std::ops::Mul<$inner> for $T {
            type Output = $T;
            fn mul(self, rhs: $inner) -> $T {
                $T(self.0 * rhs)
            }
        }

        impl std::ops::Mul<$T> for $inner {
            type Output = $T;
            fn mul(self, rhs: $T) -> $T {
                $T(rhs.0 * self)
            }
        }

        impl std::ops::Mul<usize> for $T {
            type Output = $T;
            fn mul(self, rhs: usize) -> $T {
                $T(self.0 * rhs as $inner)
            }
        }

        impl std::ops::Mul<$T> for usize {
            type Output = $T;
            fn mul(self, rhs: $T) -> $T {
                $T(rhs.0 * self as $inner)
            }
        }
    };
}

// Define a complete set of remainder operations.
macro_rules! rem {
    ($T: ident) => {
        impl<T> std::ops::Rem<T> for $T
        where
            $T: From<T>,
        {
            type Output = $T;
            fn rem(self, rhs: T) -> $T {
                $T(self.0 % <$T>::from(rhs).0)
            }
        }
    };
}

macro_rules! checked_add {
    ($T: ident) => {
        impl $T {
            /// Add two items of the same type, return None if overflow.
            pub fn checked_add(&self, other: $T) -> Option<$T> {
                self.0.checked_add(other.0).map($T)
            }
        }
    };
}

#[cfg(test)]
mod tests {

    range_u64!(Units, "units");

    #[test]
    /// Test implicit derivations for Units
    fn test_implicit_derivations() {
        // Test Clone. Note cloning within an assertion disables the clippy
        // allow, so no assertion here.
        #[allow(clippy::clone_on_copy)]
        let _ = Units(1).clone();

        // Test Default
        assert_eq!(Units::default(), Units(0));

        // Test Ord, PartialOrd
        assert!(Units::default() < Units(1));
        assert!(Units(1) >= Units::default());

        // Test Copy
        let z = Units(3);
        let mut d = z;
        d += Units(1);
        assert_eq!(z, Units(3));
        assert_eq!(d, Units(4));
    }

    #[test]
    /// Test non-arithmetic derivations that are derived explicitly
    fn test_explicit_derivations() {
        // Test From
        assert_eq!(Units::from(3u8) + Units(3), Units(6));

        // Test Deref
        assert_eq!(*Units(3) + 3, 6);

        // Test Debug
        assert_eq!(format!("{:?}", Units(3)), "Units(3)");

        // Test Display
        assert_eq!(format!("{:}", Units(3)), "3 units");
    }

    #[test]
    /// Test operations that work on an iterator of values, like sum and
    /// product.
    fn test_summary_operations() {
        // Test Sum
        assert_eq!(
            vec![Units(2), Units(3)].iter().cloned().sum::<Units>(),
            Units(5)
        );
    }

    #[test]
    /// Test addition.
    fn test_addition() {
        assert_eq!(Units(1) + Units(3), Units(4));

        let mut z = Units(1);
        z += Units(3);
        assert_eq!(z, Units(4));

        assert_eq!(Units(u64::MAX).checked_add(Units(1)), None);
    }

    #[test]
    /// Test subtraction
    fn test_subtraction() {
        assert_eq!(Units(3) - Units(1), Units(2));

        let mut z = Units(3);
        z -= Units(1);
        assert_eq!(z, Units(2));
    }

    #[test]
    /// Test multiplication
    fn test_multiplication() {
        assert_eq!(Units(3) * 2u8, Units(6));
        assert_eq!(2u8 * Units(3), Units(6));

        assert_eq!(Units(3) * 2u16, Units(6));
        assert_eq!(2u16 * Units(3), Units(6));

        assert_eq!(Units(3) * 2u32, Units(6));
        assert_eq!(2u32 * Units(3), Units(6));

        assert_eq!(Units(3) * 2u64, Units(6));
        assert_eq!(2u64 * Units(3), Units(6));

        assert_eq!(Units(3) * 2usize, Units(6));
        assert_eq!(2usize * Units(3), Units(6));
    }

    #[test]
    /// Test division and remainder together
    fn test_division_and_remainder() {
        assert_eq!(Units(3) / Units(2), 1);
        assert_eq!(Units(3) % Units(2), Units(1));

        assert_eq!(Units(5) / 2u8, Units(2));
        assert_eq!(Units(3) % 2u8, Units(1));

        assert_eq!(Units(5) / 2u16, Units(2));
        assert_eq!(Units(3) % 2u16, Units(1));

        assert_eq!(Units(5) / 2u32, Units(2));
        assert_eq!(Units(3) % 2u32, Units(1));

        assert_eq!(Units(5) / 2u64, Units(2));
        assert_eq!(Units(3) % 2u64, Units(1));

        assert_eq!(Units(5) / 2usize, Units(2));
        assert_eq!(Units(3) % 2usize, Units(1));
    }
}
