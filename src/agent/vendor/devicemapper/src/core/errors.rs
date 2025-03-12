// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*! Definition for low level error class for core methods !*/

use std::{self, path::PathBuf};

use crate::core::deviceinfo::DeviceInfo;

#[derive(Clone, Debug)]
/// Internal error for low-level devicemapper operations
pub enum Error {
    /// An error returned on failure to create a devicemapper context
    ContextInit(String),

    /// This is a generic error that can be returned when a method
    /// receives an invalid argument. Ideally, the argument should be
    /// invalid in itself, i.e., it should not be made invalid by some
    /// part of the program state or the environment.
    InvalidArgument(String),

    /// An error returned exclusively by DM methods.
    /// This error is initiated in DM::do_ioctl and returned by
    /// numerous wrapper methods.
    Ioctl(
        u8,
        Option<Box<DeviceInfo>>,
        Option<Box<DeviceInfo>>,
        Box<nix::Error>,
    ),

    /// An error returned when the response exceeds the maximum possible
    /// size of the ioctl buffer.
    IoctlResultTooLarge,

    /// An error returned on failure to get metadata for a device
    MetadataIo(PathBuf, String),

    /// An error returned on general IO failure
    GeneralIo(String),

    /// An error synchronizing with udev
    UdevSync(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ContextInit(err) => {
                write!(f, "DM context not initialized due to IO error: {err}")
            }
            Error::InvalidArgument(err) => write!(f, "invalid argument: {err}"),
            Error::Ioctl(op, hdr_in, hdr_out, err) => write!(
                f,
                "low-level ioctl error due to nix error; ioctl number: {op}, input header: {hdr_in:?}, header result: {hdr_out:?}, error: {err}"
            ),
            Error::IoctlResultTooLarge => write!(
                f,
                "ioctl result too large for maximum buffer size: {} bytes",
                u32::MAX
            ),
            Error::MetadataIo(device_path, err) => write!(
                f,
                "failed to stat metadata for device at {} due to IO error: {}",
                device_path.display(),
                err
            ),
            Error::GeneralIo(err) => {
                write!(f, "failed to perform operation due to IO error: {err}")
            }
            Error::UdevSync(err) => {
                write!(f, "failed to perform udev sync operation: {}", err)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Ioctl(_, _, _, err) => Some(err),
            _ => None,
        }
    }
}
