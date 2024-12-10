// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Modules that support testing.

mod logger;
mod loopbacked;
mod test_lib;

pub use self::{
    logger::init_logger,
    loopbacked::test_with_spec,
    test_lib::{
        blkdev_size, test_name, test_string, test_uuid, udev_settle, xfs_create_fs, xfs_set_uuid,
    },
};
