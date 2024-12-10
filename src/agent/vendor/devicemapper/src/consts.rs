// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
/// International Electrotechnical Commission Units Standards
pub mod IEC {
    /// kibi
    pub const Ki: u64 = 1024;
    /// mebi
    pub const Mi: u64 = 1024 * Ki;
    /// gibi
    pub const Gi: u64 = 1024 * Mi;
    /// tebi
    pub const Ti: u64 = 1024 * Gi;
    /// pebi
    pub const Pi: u64 = 1024 * Ti;
    /// exbi
    pub const Ei: u64 = 1024 * Pi;
    // Ei is the maximum IEC unit expressible in u64.
}
