// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Build script for the runtime-rs hypervisor crate.
//!
//! When the `openvmm` feature is enabled, this regenerates the checked-in
//! OpenVMM TTRPC `vmservice` bindings from the vendored `protos/vmservice.proto`
//! using `ttrpc-codegen` (the same pure-Rust toolchain as `src/libs/protocols`).
//! The vendored proto is fetched on demand by the crate `Makefile`
//! (`make update-proto`) and pinned via `versions.yaml`; this script only
//! compiles the committed proto, so builds remain hermetic and offline-capable.

use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Write};

/// Replace every occurrence of `from` with `to` in the file at `path`.
///
/// Returns an error if `from` does not appear in the file, so a patch that has
/// silently become a no-op (e.g. the generated output changed shape) fails the
/// build instead of passing unnoticed.
fn replace_in_file(path: &str, from: &str, to: &str) -> std::io::Result<()> {
    let mut contents = String::new();
    File::open(path)?.read_to_string(&mut contents)?;

    let replaced = contents.replace(from, to);
    if replaced == contents {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("expected to find {from:?} in {path}, but it was not present"),
        ));
    }

    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?
        .write_all(replaced.as_bytes())?;

    Ok(())
}

fn main() {
    // The generated bindings are only needed for the external OpenVMM TTRPC
    // backend. The output is checked in, so builds without the `openvmm`
    // feature perform no codegen at all.
    if std::env::var("CARGO_FEATURE_OPENVMM").is_err() {
        return;
    }

    use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};

    let protos = ["protos/vmservice.proto"];

    // Only regenerate when the vendored proto (or this script) changes.
    println!("cargo:rerun-if-changed=build.rs");
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }

    Codegen::new()
        .out_dir("src/openvmm")
        .inputs(protos)
        .include("protos")
        .customize(Customize {
            async_all: true,
            ..Default::default()
        })
        .rust_protobuf()
        .rust_protobuf_customize(
            ProtobufCustomize::default()
                .gen_mod_rs(false)
                .generate_getter(true)
                .generate_accessors(true),
        )
        .run()
        .expect("failed to generate OpenVMM vmservice ttrpc bindings");

    // ttrpc-codegen (compiler 0.8) lowercases the proto service name `VM` to
    // `Vm` when emitting the ttrpc service path, yielding "vmservice.Vm".
    // OpenVMM's `mesh_rpc` server registers the service as "vmservice.VM"
    // (proto `package` "." service name), and ttrpc matches the service path
    // verbatim, so without this fix every call is rejected as an unknown
    // service. Patch the generated client/server to use the on-wire name.
    replace_in_file(
        "src/openvmm/vmservice_ttrpc.rs",
        "\"vmservice.Vm\"",
        "\"vmservice.VM\"",
    )
    .expect("failed to patch generated vmservice ttrpc service name");
}
