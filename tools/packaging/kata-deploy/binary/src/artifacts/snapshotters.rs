// Copyright (c) 2019 Kata Containers community
// Copyright (c) 2025 NVIDIA Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::{Config, NYDUS_FOR_KATA_TEE};
use crate::runtime::containerd;
use crate::utils;
use crate::utils::toml as toml_utils;
use anyhow::Result;
use log::{info, warn};
use std::fs;

/// Build the `mkfs_options` array for containerd's EROFS differ.
///
/// Every option here exists to make a layer's EROFS image a pure function of the
/// layer's content, so that its dm-verity root hash can be predicted ahead of time.
///
/// Deliberately absent: `-U`. The filesystem UUID is the last source of
/// non-determinism once the timestamp and sort order are pinned, but containerd's
/// differ already supplies one of its own, derived from the layer's descriptor:
///
///     uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+desc.Digest))
///
/// and appends it *after* the options configured here. mkfs.erofs honours the last
/// `-U` on the command line, so anything we pass is silently discarded. containerd's
/// value is strictly better than a fixed one: it is deterministic *and* distinct per
/// layer, so identical layer content in different images does not collapse onto a
/// shared UUID. See RM-46.
fn erofs_mkfs_options() -> String {
    "[\"-T0\",\"--mkfs-time\",\"--sort=none\"]".to_string()
}

/// Bind the transfer service's unpacker for the `erofs` snapshotter to the `erofs`
/// differ, so layer construction cannot silently fall back to a path that produces
/// no dm-verity metadata. See RM-50 and the call site for why this matters.
fn erofs_unpack_config() -> String {
    "[{platform = \"linux/amd64\", snapshotter = \"erofs\", differ = \"erofs\"}, \
     {platform = \"linux/arm64\", snapshotter = \"erofs\", differ = \"erofs\"}]"
        .to_string()
}
use std::path::Path;

/// Reject dm-verity on the merged EROFS layout (RM-40).
///
/// Split out from `configure_erofs_snapshotter` so the rule itself can be tested
/// without constructing a full `Config` and touching the filesystem.
fn check_dmverity_requires_unmerged(erofs_dmverity: bool, unmerged: bool) -> Result<()> {
    if erofs_dmverity && !unmerged {
        return Err(anyhow::anyhow!(
            "erofs snapshotter: EROFS_DMVERITY requires EROFS_MERGE_MODE=unmerged. \
             In merged mode the dm-verity options are stripped before the storage is \
             built, so layer content would be unverified despite dm-verity appearing \
             to be enabled."
        ));
    }
    Ok(())
}

pub async fn configure_erofs_snapshotter(config: &Config, configuration_file: &Path) -> Result<()> {
    info!("Configuring erofs-snapshotter");

    // "unmerged" mode keeps each image layer as its own per-layer `layer.erofs`
    // (containerd's default, non-fsmerged layout), which is the only layout the
    // Go runtime can consume. In the default "merged" mode we force containerd
    // to merge layers into a single `fsmeta.erofs`, which is runtime-rs only.
    let unmerged = config.erofs_merge_mode.as_deref() == Some("unmerged");

    // dm-verity layer integrity only exists in unmerged mode (RM-40).
    //
    // The GPT+VMDK path gives each layer its own block device and attaches
    // dm-verity options per partition. The fsmerge path builds a single merged
    // image and strips every `X-kata.` option before constructing the storage, so
    // no roothash, salt or hashoffset can reach the guest even in principle.
    // Enabling dm-verity on a merged deployment therefore produces a containerd
    // config that genuinely writes per-layer dm-verity metadata which the runtime
    // then silently ignores -- unverified container content on a deployment the
    // operator has every reason to believe is verified. In a strict guest RM-31
    // catches it, but only as an unexplained startup failure. Refuse the
    // combination outright, mirroring the Go-shim guard above.
    if config.erofs_dmverity && !unmerged {
        warn!("##########################################################################");
        warn!("#                                                                        #");
        warn!("#  EROFS dm-verity was requested with the merged layer layout.           #");
        warn!("#                                                                        #");
        warn!("#  dm-verity verifies erofs lower layers per block device, which only    #");
        warn!("#  exists in unmerged mode. In merged mode the metadata is generated     #");
        warn!("#  and then discarded, leaving container content UNVERIFIED while        #");
        warn!("#  appearing to be protected.                                            #");
        warn!("#                                                                        #");
        warn!("#  Set EROFS_MERGE_MODE=unmerged, or disable EROFS_DMVERITY.             #");
        warn!("#                                                                        #");
        warn!("##########################################################################");
    }
    check_dmverity_requires_unmerged(config.erofs_dmverity, unmerged)?;

    // The Go runtime does not support fsmerged EROFS (fsmeta.erofs).
    // If the snapshotter handler mapping explicitly pairs a Go shim with
    // erofs in the (default) merged mode, that is a hard misconfiguration —
    // bail out so the operator fixes the mapping instead of hitting cryptic
    // runtime errors later. In "unmerged" mode the Go runtime is supported, so
    // skip this guard.
    if !unmerged {
        if let Some(mapping) = config.snapshotter_handler_mapping_for_arch.as_ref() {
            let mut go_shims_on_erofs = Vec::new();
            for entry in mapping.split(',') {
                let parts: Vec<&str> = entry.split(':').collect();
                if parts.len() == 2 && parts[1] == "erofs" && !utils::is_rust_shim(parts[0]) {
                    go_shims_on_erofs.push(parts[0].to_string());
                }
            }
            if !go_shims_on_erofs.is_empty() {
                warn!("##########################################################################");
                warn!("#                                                                        #");
                warn!("#  Go runtime shim(s) mapped to the erofs snapshotter:                   #");
                for s in &go_shims_on_erofs {
                    warn!("#    - {:<64} #", s);
                }
                warn!("#                                                                        #");
                warn!(
                    "#  The Go runtime does NOT support fsmerged EROFS (fsmeta.erofs).         #"
                );
                warn!("#  Only runtime-rs shims are supported with merged erofs. Set            #");
                warn!("#  EROFS_MERGE_MODE=unmerged to use the Go runtime with erofs.           #");
                warn!("#                                                                        #");
                warn!("##########################################################################");
                return Err(anyhow::anyhow!(
                    "erofs snapshotter: Go runtime shim(s) [{}] cannot be mapped to merged erofs. \
                     The Go runtime does not support fsmerged EROFS. \
                     Set EROFS_MERGE_MODE=unmerged, remove these shims from \
                     SNAPSHOTTER_HANDLER_MAPPING, or switch them to runtime-rs.",
                    go_shims_on_erofs.join(", ")
                ));
            }
        }
    }

    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.cri.v1.images\".discard_unpacked_layers",
        "false",
    )?;

    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.service.v1.diff-service\".default",
        "[\"erofs\",\"walking\"]",
    )?;

    // dm-verity is orthogonal to rw-layer backing — it verifies lower (erofs)
    // layers via device-mapper regardless of whether the upper rw-layer lives on
    // disk or in memory. When dm-verity is enabled, fsverity and immutable are
    // disabled on the snapshotter side in favor of dm-verity.
    let use_dmverity = config.erofs_dmverity;

    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.snapshotter.v1.erofs\".enable_fsverity",
        "true",
    )?;
    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.snapshotter.v1.erofs\".set_immutable",
        "true",
    )?;

    if use_dmverity {
        toml_utils::set_toml_value(
            configuration_file,
            ".plugins.\"io.containerd.snapshotter.v1.erofs\".dmverity_mode",
            "\"auto\"",
        )?;
    }

    // Erofs differ plugin options (requires erofs-utils >= 1.8.2 on the host).
    //
    // These make a layer's EROFS image, and therefore its dm-verity root hash, a
    // deterministic function of the layer content: `-T0 --mkfs-time` pins the build
    // timestamp and `--sort=none` removes tar ordering variance. The remaining
    // variable, the filesystem UUID, is pinned by containerd itself to a value
    // derived from the layer digest -- see erofs_mkfs_options(). Reproducibility is
    // what lets a policy generator declare the hash a layer must have (RM-38/RM-46).
    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.differ.v1.erofs\".mkfs_options",
        &erofs_mkfs_options(),
    )?;
    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.differ.v1.erofs\".enable_tar_index",
        "false",
    )?;

    // Force image pulls through the transfer service and bind it explicitly to the
    // EROFS differ (RM-50).
    //
    // Only the differ builds a layer the way the policy expects: with the
    // reproducibility options above, containerd's derived `-U`, and a dm-verity hash
    // tree. When it is bypassed -- as the client-side unpacker used by
    // `ctr image pull --local` does -- the EROFS *snapshotter* converts the extracted
    // directory itself with a bare `mkfs.erofs --quiet -Enoinline_data <out> <dir>`.
    // That embeds live mtimes and a random UUID and writes no dm-verity metadata at
    // all, even with `enable_dmverity = true`. Such a layer can never match a
    // policy-declared root hash, so it fails closed, but it fails as an opaque mount
    // refusal. Stating both settings makes the verified configuration explicit rather
    // than a happy accident of containerd's fallback ordering.
    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.cri.v1.images\".use_local_image_pull",
        "false",
    )?;
    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.transfer.v1.local\".unpack_config",
        &erofs_unpack_config(),
    )?;

    toml_utils::set_toml_value(
        configuration_file,
        ".plugins.\"io.containerd.snapshotter.v1.erofs\".default_size",
        "\"10G\"",
    )?;
    // In the default "merged" mode, force containerd to merge all layers into a
    // single fsmeta.erofs (max_unmerged_layers = 0). In "unmerged" mode we delete
    // any previously-written value so each layer stays a separate layer.erofs,
    // which the Go runtime requires.
    //
    // Because kata-deploy edits the containerd config in place, switching from
    // merged to unmerged must actively remove the old `max_unmerged_layers = 0`
    // left behind by a previous install. Otherwise the stale `0` would keep
    // forcing the merged layout and break Go-runtime compatibility.
    if !unmerged {
        toml_utils::set_toml_value(
            configuration_file,
            ".plugins.\"io.containerd.snapshotter.v1.erofs\".max_unmerged_layers",
            "0",
        )?;
    } else {
        toml_utils::delete_toml_value(
            configuration_file,
            ".plugins.\"io.containerd.snapshotter.v1.erofs\".max_unmerged_layers",
        )?;
    }

    Ok(())
}

pub async fn configure_nydus_snapshotter(
    config: &Config,
    configuration_file: &Path,
    pluginid: &str,
) -> Result<()> {
    info!("Configuring {NYDUS_FOR_KATA_TEE}");

    let nydus = match config.multi_install_suffix.as_ref() {
        Some(suffix) if !suffix.is_empty() => format!("{NYDUS_FOR_KATA_TEE}-{suffix}"),
        _ => NYDUS_FOR_KATA_TEE.to_string(),
    };

    let containerd_nydus = nydus.clone();

    toml_utils::set_toml_value(
        configuration_file,
        &format!(".plugins.{pluginid}.disable_snapshot_annotations"),
        "false",
    )?;

    toml_utils::set_toml_value(
        configuration_file,
        &format!(".proxy_plugins.\"{nydus}\".type"),
        "\"snapshot\"",
    )?;
    toml_utils::set_toml_value(
        configuration_file,
        &format!(".proxy_plugins.\"{nydus}\".address"),
        &format!("\"/run/{containerd_nydus}/containerd-nydus-grpc.sock\""),
    )?;
    toml_utils::set_toml_value(
        configuration_file,
        &format!(".proxy_plugins.\"{nydus}\".exports.root"),
        &format!("\"/var/lib/{nydus}\""),
    )?;

    Ok(())
}

pub async fn configure_snapshotter(
    snapshotter: &str,
    runtime: &str,
    config: &Config,
) -> Result<()> {
    // Get all paths and drop-in capability in one call
    let paths = config.get_containerd_paths(runtime).await?;

    // Runtime plugin id (from paths or by reading config), then map to table where disable_snapshot_annotations lives.
    let runtime_plugin_id = match &paths.plugin_id {
        Some(id) => id.as_str(),
        None => containerd::get_containerd_pluginid(&paths.config_file, runtime)?,
    };
    let pluginid =
        containerd::pluginid_for_snapshotter_annotations(runtime_plugin_id, &paths.config_file)?;

    let configuration_file: std::path::PathBuf = if paths.use_drop_in {
        // Only add /host prefix if path is not in /etc/containerd (which is mounted from host)
        let base_path = if paths.drop_in_file.starts_with("/etc/containerd/") {
            Path::new(&paths.drop_in_file).to_path_buf()
        } else {
            // Need to add /host prefix for paths outside /etc/containerd
            let drop_in_path = paths.drop_in_file.trim_start_matches('/');
            Path::new("/host").join(drop_in_path)
        };

        log::debug!("Snapshotter using drop-in config file: {:?}", base_path);
        base_path
    } else {
        log::debug!("Snapshotter using main config file: {}", paths.config_file);
        Path::new(&paths.config_file).to_path_buf()
    };

    match snapshotter {
        "nydus" => {
            configure_nydus_snapshotter(config, &configuration_file, pluginid).await?;

            let nydus_snapshotter = match config.multi_install_suffix.as_ref() {
                Some(suffix) if !suffix.is_empty() => format!("{NYDUS_FOR_KATA_TEE}-{suffix}"),
                _ => NYDUS_FOR_KATA_TEE.to_string(),
            };

            utils::host_systemctl(&["restart", &nydus_snapshotter])?;
        }
        "erofs" => {
            configure_erofs_snapshotter(config, &configuration_file).await?;
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported snapshotter: {snapshotter}"));
        }
    }

    Ok(())
}

pub async fn install_nydus_snapshotter(config: &Config) -> Result<()> {
    info!("Deploying {NYDUS_FOR_KATA_TEE}");

    let nydus_snapshotter = match config.multi_install_suffix.as_ref() {
        Some(suffix) if !suffix.is_empty() => format!("{NYDUS_FOR_KATA_TEE}-{suffix}"),
        _ => NYDUS_FOR_KATA_TEE.to_string(),
    };

    // Stop the service if it is currently running so we can replace the binaries safely.
    let _ = utils::host_systemctl(&["stop", &format!("{nydus_snapshotter}.service")]);

    // The nydus data directory (/var/lib/nydus-for-kata-tee) is intentionally preserved
    // across reinstalls.  Removing it would create a split-brain state: the nydus backend
    // would start empty while containerd's BoltDB (meta.db) still holds snapshot records
    // from the previous run.  Any subsequent image pull then fails with:
    //
    //   "unable to prepare extraction snapshot:
    //    target snapshot \"sha256:...\": already exists"
    //
    // because the metadata layer finds the target chainID in BoltDB and returns AlreadyExists
    // before the backend is consulted, but when Stat() delegates to the (now empty) backend
    // it gets NotFound — tripping the unpacker's retry loop.
    //
    // Cleaning up containerd's meta.db before wiping the dir was attempted, but that cleanup
    // itself requires the nydus gRPC service to be reachable (ctr snapshots rm calls the
    // backend).  If the service was stopped or crashed before the cleanup ran, the cleanup
    // silently fails and the split-brain state reappears.
    //
    // The correct invariant is simpler: meta.db and the nydus backend must always agree.
    // Preserving the data directory across reinstalls guarantees this at zero cost.
    // Any stale snapshots from previous workloads are naturally garbage-collected by
    // containerd once the images that reference them are removed.

    let config_guest_pulling = "/opt/kata-artifacts/nydus-snapshotter/config-guest-pulling.toml";
    let nydus_snapshotter_service =
        "/opt/kata-artifacts/nydus-snapshotter/nydus-snapshotter.service";

    let mut config_content = fs::read_to_string(config_guest_pulling)?;
    config_content = config_content.replace(
        "@SNAPSHOTTER_ROOT_DIR@",
        &format!("/var/lib/{nydus_snapshotter}"),
    );
    config_content = config_content.replace(
        "@SNAPSHOTTER_GRPC_SOCKET_ADDRESS@",
        &format!("/run/{nydus_snapshotter}/containerd-nydus-grpc.sock"),
    );
    config_content = config_content.replace(
        "@NYDUS_OVERLAYFS_PATH@",
        &format!(
            "{}/{NYDUS_FOR_KATA_TEE}/nydus-overlayfs",
            &config
                .host_install_dir
                .strip_prefix("/host")
                .unwrap_or(&config.host_install_dir)
        ),
    );

    let mut service_content = fs::read_to_string(nydus_snapshotter_service)?;
    service_content = service_content.replace(
        "@CONTAINERD_NYDUS_GRPC_BINARY@",
        &format!(
            "{}/{NYDUS_FOR_KATA_TEE}/containerd-nydus-grpc",
            &config
                .host_install_dir
                .strip_prefix("/host")
                .unwrap_or(&config.host_install_dir)
        ),
    );
    service_content = service_content.replace(
        "@CONFIG_GUEST_PULLING@",
        &format!(
            "{}/{NYDUS_FOR_KATA_TEE}/config-guest-pulling.toml",
            &config
                .host_install_dir
                .strip_prefix("/host")
                .unwrap_or(&config.host_install_dir)
        ),
    );

    fs::create_dir_all(format!("{}/{NYDUS_FOR_KATA_TEE}", config.host_install_dir))?;

    // Remove existing binaries before copying new ones.
    // This is crucial for atomic updates (same pattern as copy_artifacts in install.rs):
    // - If the file is in use (e.g., a running binary), the old inode stays alive
    // - The new copy creates a new inode
    // - Running processes keep using the old inode until they exit
    // - New processes use the new file immediately
    // Without this, fs::copy would fail with ETXTBSY ("Text file busy") if the
    // nydus-for-kata-tee service is still running from a previous installation.
    let grpc_binary = format!(
        "{}/{NYDUS_FOR_KATA_TEE}/containerd-nydus-grpc",
        config.host_install_dir
    );
    let overlayfs_binary = format!(
        "{}/{NYDUS_FOR_KATA_TEE}/nydus-overlayfs",
        config.host_install_dir
    );
    for binary in [&grpc_binary, &overlayfs_binary] {
        match fs::remove_file(binary) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    fs::copy(
        "/opt/kata-artifacts/nydus-snapshotter/containerd-nydus-grpc",
        &grpc_binary,
    )?;
    fs::copy(
        "/opt/kata-artifacts/nydus-snapshotter/nydus-overlayfs",
        &overlayfs_binary,
    )?;

    fs::write(
        format!(
            "{}/{NYDUS_FOR_KATA_TEE}/config-guest-pulling.toml",
            config.host_install_dir
        ),
        config_content,
    )?;

    fs::write(
        format!("/host/etc/systemd/system/{nydus_snapshotter}.service"),
        service_content,
    )?;

    utils::host_systemctl(&["daemon-reload"])?;
    utils::host_systemctl(&["enable", &format!("{nydus_snapshotter}.service")])?;

    Ok(())
}

pub async fn uninstall_nydus_snapshotter(config: &Config) -> Result<()> {
    info!("Removing deployed {NYDUS_FOR_KATA_TEE}");

    let nydus_snapshotter = match config.multi_install_suffix.as_ref() {
        Some(suffix) if !suffix.is_empty() => format!("{NYDUS_FOR_KATA_TEE}-{suffix}"),
        _ => NYDUS_FOR_KATA_TEE.to_string(),
    };

    utils::host_systemctl(&["disable", "--now", &format!("{nydus_snapshotter}.service")])?;

    fs::remove_file(format!(
        "/host/etc/systemd/system/{nydus_snapshotter}.service"
    ))
    .ok();
    fs::remove_dir_all(format!("{}/{NYDUS_FOR_KATA_TEE}", config.host_install_dir)).ok();

    // The nydus data directory (/var/lib/nydus-for-kata-tee) is intentionally preserved.
    // See install_nydus_snapshotter for the full explanation: meta.db and the nydus backend
    // must always agree, and the only way to guarantee that without complex, fragile cleanup
    // logic is to never remove the data directory.  After uninstall, containerd is
    // reconfigured without the nydus proxy_plugins entry and restarted, so the remaining
    // snapshot records in meta.db are completely dormant — nothing will use them.  If nydus
    // is reinstalled later the data directory is still present and both sides remain in sync.

    utils::host_systemctl(&["daemon-reload"])?;

    Ok(())
}

pub async fn install_snapshotter(snapshotter: &str, config: &Config) -> Result<()> {
    match snapshotter {
        "erofs" => {
            // erofs is a containerd built-in snapshotter, no installation needed
        }
        "nydus" => {
            install_nydus_snapshotter(config).await?;
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported snapshotter: {snapshotter}"));
        }
    }

    Ok(())
}

pub async fn uninstall_snapshotter(snapshotter: &str, config: &Config) -> Result<()> {
    match snapshotter {
        "nydus" => {
            uninstall_nydus_snapshotter(config).await?;
        }
        _ => {
            // No cleanup needed for erofs
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The differ options must pin every input that would otherwise vary between
    /// builds of identical layer content. Dropping any of these silently breaks
    /// reproducibility of the dm-verity root hash, which a policy generator relies
    /// on being able to predict, so assert on each one individually.
    #[test]
    fn erofs_mkfs_options_pin_all_sources_of_nondeterminism() {
        let opts = erofs_mkfs_options();

        // Build timestamp.
        assert!(opts.contains("\"-T0\""), "missing -T0 in {opts}");
        assert!(opts.contains("\"--mkfs-time\""), "missing --mkfs-time in {opts}");
        // Tar entry ordering.
        assert!(opts.contains("\"--sort=none\""), "missing --sort=none in {opts}");
    }

    /// RM-40: dm-verity on the merged layout is the one combination that must be
    /// refused. It is not merely unsupported -- it produces a deployment that looks
    /// verified and is not, because the runtime strips the dm-verity options before
    /// building the storage. Every other combination must still be allowed.
    #[test]
    fn dmverity_is_refused_on_the_merged_layout() {
        assert!(check_dmverity_requires_unmerged(true, false).is_err());

        assert!(check_dmverity_requires_unmerged(true, true).is_ok());
        assert!(check_dmverity_requires_unmerged(false, false).is_ok());
        assert!(check_dmverity_requires_unmerged(false, true).is_ok());
    }

    /// The error has to name both knobs, since the operator set one of them and has
    /// no reason to suspect the other is involved.
    #[test]
    fn dmverity_merge_mode_error_names_both_settings() {
        let err = check_dmverity_requires_unmerged(true, false).unwrap_err().to_string();
        assert!(err.contains("EROFS_DMVERITY"), "{err}");
        assert!(err.contains("EROFS_MERGE_MODE=unmerged"), "{err}");
    }

    /// The unpack binding is the difference between layers that carry dm-verity and
    /// layers that silently do not, so it must name the erofs differ for every
    /// platform we build and must be valid TOML -- an unparseable value would take
    /// containerd down rather than degrade it (RM-50).
    #[test]
    fn erofs_unpack_config_binds_the_differ_and_is_valid_toml() {
        let cfg = erofs_unpack_config();
        let doc: toml_edit::DocumentMut = format!("unpack_config = {cfg}")
            .parse()
            .expect("unpack_config must be TOML");
        let entries = doc["unpack_config"]
            .as_array()
            .expect("array of inline tables");
        assert_eq!(entries.len(), 2, "one entry per supported platform");
        let mut platforms = Vec::new();
        for entry in entries.iter() {
            let table = entry.as_inline_table().expect("inline table");
            assert_eq!(table["snapshotter"].as_str(), Some("erofs"));
            assert_eq!(
                table["differ"].as_str(),
                Some("erofs"),
                "bypassing the erofs differ produces layers with no dm-verity metadata"
            );
            platforms.push(table["platform"].as_str().unwrap().to_string());
        }
        assert!(platforms.contains(&"linux/amd64".to_string()));
        assert!(platforms.contains(&"linux/arm64".to_string()));
    }

    /// containerd's differ appends its own `-U <uuid-of-layer-digest>` after these
    /// options, and mkfs.erofs honours the last one, so passing our own would be
    /// dead configuration that misleads a reader into thinking reproducibility
    /// depends on it. Guard against it being reintroduced (RM-46).
    #[test]
    fn erofs_mkfs_options_do_not_pass_a_uuid() {
        let opts = erofs_mkfs_options();
        assert!(
            !opts.contains("-U"),
            "containerd overrides any -U we pass; remove it from {opts}"
        );
    }

    /// The options are written into containerd's TOML as a literal array, so a
    /// quoting mistake would produce a malformed config rather than a build error.
    #[test]
    fn erofs_mkfs_options_parse_as_a_toml_string_array() {
        let doc = format!("opts = {}", erofs_mkfs_options())
            .parse::<toml_edit::DocumentMut>()
            .expect("mkfs_options is not valid TOML");
        let arr = doc["opts"].as_array().expect("not an array");
        assert_eq!(
            arr.iter()
                .map(|v| v.as_str().expect("non-string element"))
                .collect::<Vec<_>>(),
            vec!["-T0", "--mkfs-time", "--sort=none"]
        );
    }
}
