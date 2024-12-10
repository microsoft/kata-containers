// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use semver::Version;

use devicemapper_sys::{DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCHLEVEL};

// List of DM ioctl interface versions that introduce new ioctl commands
static DM_VERSIONS: &[&str] = &["4.1.0", "4.2.0", "4.6.0", "4.37.0", "4.41.0"];

fn main() {
    let version = Version::parse(&format!(
        "{DM_VERSION_MAJOR}.{DM_VERSION_MINOR}.{DM_VERSION_PATCHLEVEL}"
    ))
    .expect("simple version string is not parseable");

    for ver in DM_VERSIONS.iter().take_while(|ver_string| {
        let iter_version = Version::parse(ver_string).expect("Could not parse version");
        version >= iter_version
    }) {
        println!(
            "cargo:rustc-cfg=devicemapper{}supported",
            ver.split('.').take(2).collect::<Vec<_>>().join("")
        );
    }
}
