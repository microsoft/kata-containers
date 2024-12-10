// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{env::var, path::PathBuf};

use bindgen::Builder;

fn main() {
    // Generate bindings for dm-ioctl.h and libdevmapper.h
    let bindings = Builder::default()
        .header("dm.h")
        .allowlist_var("DM.*")
        .allowlist_type("__u16")
        .allowlist_type("dm_ioctl")
        .allowlist_type("dm_name_list")
        .allowlist_type("dm_target_deps")
        .allowlist_type("dm_target_msg")
        .allowlist_type("dm_target_spec")
        .allowlist_type("dm_target_versions")
        .derive_debug(true)
        .derive_default(true)
        .generate()
        .expect("Could not generate dm.h bindings");

    let mut bindings_path = PathBuf::from(var("OUT_DIR").unwrap());
    bindings_path.push("dm-bindings.rs");
    bindings
        .write_to_file(&bindings_path)
        .expect("Could not write bindings to file");

    // Generate bindings for SysV Semaphore IPC
    let bindings = Builder::default()
        .header("sem.h")
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .allowlist_var("GET.*")
        .allowlist_var("SET.*")
        .allowlist_var("SEM_.*")
        .allowlist_type("semun");

    #[cfg(target_env = "musl")]
    let bindings = bindings
        .allowlist_type("seminfo")
        .allowlist_type("semid_ds");

    let bindings = bindings
        .derive_debug(true)
        .derive_default(true)
        .generate()
        .expect("Could not generate sem.h bindings");

    let mut bindings_path = PathBuf::from(var("OUT_DIR").unwrap());
    bindings_path.push("sem-bindings.rs");
    bindings
        .write_to_file(&bindings_path)
        .expect("Could not write bindings to file");
}
