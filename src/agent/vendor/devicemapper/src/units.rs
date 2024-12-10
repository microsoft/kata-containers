// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// disk sector size in bytes
pub const SECTOR_SIZE: usize = 512;

/// a kernel defined block size constant for any DM meta device
/// a DM meta device may store cache device or thinpool device metadata
/// defined in drivers/md/persistent-data/dm-space-map-metadata.h as
/// DM_SM_METADATA_BLOCK_SIZE.
const META_BLOCK_SIZE: Sectors = Sectors(8);

/// The maximum size of a metadata device.
/// defined in drivers/md/persistent-data/dm-space-map-metadata.h as
/// DM_SM_METADATA_MAX_BLOCKS.
/// As far as I can tell, this is not a limit on the size of a designated
/// metadata device, but instead on the possible usage of that device.
#[allow(dead_code)]
const MAX_META_DEV_SIZE: MetaBlocks = MetaBlocks(255 * ((1 << 14) - 64));

range_u64!(
    /// A type for data blocks
    DataBlocks,
    "data blocks"
);

range_u64!(
    /// A type for meta blocks
    MetaBlocks,
    "meta blocks"
);

impl MetaBlocks {
    /// Return the number of Sectors in the MetaBlocks.
    pub fn sectors(self) -> Sectors {
        self.0 * META_BLOCK_SIZE
    }
}

range_u128!(
    /// A type for bytes
    Bytes,
    "bytes"
);

impl Bytes {
    /// Return the number of Sectors fully contained in these bytes.
    pub fn sectors(self) -> Sectors {
        Sectors((self.0 / SECTOR_SIZE as u128) as u64)
    }
}

range_u64!(
    /// A type for sectors
    Sectors,
    "sectors"
);

impl Sectors {
    /// The number of bytes in these sectors.
    pub fn bytes(self) -> Bytes {
        // Keep both as u128 before multiplication or overflow could occur
        Bytes(u128::from(self.0) * SECTOR_SIZE as u128)
    }

    /// The number of whole metablocks contained in these sectors.
    pub fn metablocks(self) -> MetaBlocks {
        MetaBlocks(self / META_BLOCK_SIZE)
    }
}
