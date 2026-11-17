// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//
// Handle multi-layer EROFS rootfs.
//
// The containerd erofs snapshotter sends the active snapshot as either:
// - ext4 rwlayer.img + erofs lower + overlay when host rw backing is enabled.
// - erofs lower + overlay when default_size="0"; the agent then uses a
//   guest-memory upper directory under /run.
//
// The overlay mount may be handled by the guest agent if it contains "{{"
// templates in upperdir/workdir.

use super::{Rootfs, ROOTFS};
use crate::{
    block_device::agent_storage_source_from_block_config,
    share_fs::{do_get_guest_path, do_get_host_path},
};
use agent::Storage;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hypervisor::{
    device::{
        device_manager::{do_handle_device, get_block_device_info, DeviceManager},
        DeviceConfig, DeviceType,
    },
    virtio_blk_modern::BlockSourceFormat,
    BlockConfigModern, BlockDeviceAio,
};
use kata_types::mount::Mount;
use kata_types::{
    gpt_disk::{
        calculate_gpt_layout, extract_dmverity_annotation, extract_snapshot_id,
        generate_dmverity_options, generate_full_gpt_image, generate_gpt_metadata,
        generate_padding_file, get_erofs_layer_size, parse_dmverity_metadata_file, ErofsLayer,
        GptDiskLayout, GptMetadataFiles,
    },
    vmdk::VmdkConfig,
};
use nix::fcntl::{posix_fadvise, PosixFadviseAdvice};
use oci_spec::runtime as oci;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// EROFS rootfs type identifier
pub(crate) const EROFS_ROOTFS_TYPE: &str = "erofs";
/// RW layer rootfs type identifier, used for multi-layer EROFS as the writable upper layer
/// Typically ext4 format, but can be extended to other fs types in the future.
pub(crate) const RW_LAYER_ROOTFS_TYPE: &str = "ext4";
/// VMDK file extension for merged EROFS image
const EROFS_MERGED_VMDK: &str = "merged_fs.vmdk";
const EROFS_PMEM_IMAGE: &str = "erofs-pmem.raw";
const PMEM_NAMESPACE_ALIGNMENT: u64 = 2 * 1024 * 1024;
const PMEM_PAGE_SIZE: u64 = 4096;

fn pmem_namespace_superblock(payload_size: u64) -> [u8; 4096] {
    // Linux nd_pfn_sb v1.4, PFN_MODE_RAM: page metadata must not write to the image.
    let mut sb = [0u8; 4096];
    sb[..16].copy_from_slice(b"NVDIMM_PFN_INFO\0");
    sb[16..32].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    sb[52..54].copy_from_slice(&1u16.to_le_bytes());
    sb[54..56].copy_from_slice(&4u16.to_le_bytes());
    sb[56..64].copy_from_slice(&PMEM_NAMESPACE_ALIGNMENT.to_le_bytes());
    sb[64..72].copy_from_slice(&(payload_size / PMEM_PAGE_SIZE).to_le_bytes());
    sb[72..76].copy_from_slice(&1u32.to_le_bytes());
    sb[84..88].copy_from_slice(&(PMEM_NAMESPACE_ALIGNMENT as u32).to_le_bytes());
    sb[88..92].copy_from_slice(&(PMEM_PAGE_SIZE as u32).to_le_bytes());
    let (mut low, mut high) = (0u32, 0u32);
    for word in sb.chunks_exact(4) {
        low = low.wrapping_add(u32::from_le_bytes([word[0], word[1], word[2], word[3]]));
        high = high.wrapping_add(low);
    }
    sb[4088..].copy_from_slice(&((u64::from(high) << 32) | u64::from(low)).to_le_bytes());
    sb
}

fn validate_pmem_layer(mount: &Mount) -> Result<()> {
    if mount.options.iter().any(|o| o.starts_with("device=")) {
        return Err(anyhow!(
            "experimental_erofs_pmem requires independent, self-contained EROFS layers"
        ));
    }
    let mut image = fs::File::open(&mount.source)?;
    image.seek(SeekFrom::Start(1024))?;
    let mut superblock = [0u8; 128];
    image.read_exact(&mut superblock)?;
    // Reject compression-capable layouts conservatively, including legacy LZ4.
    if superblock[..4] != [0xe2, 0xe1, 0xf5, 0xe0]
        || superblock[12] != 12
        || superblock[80..84] != [0; 4]
        || superblock[84..88] != [0; 4]
        || superblock[88..90] != [0; 2]
    {
        return Err(anyhow!(
            "experimental_erofs_pmem requires uncompressed, self-contained 4 KiB EROFS layers: {}",
            mount.source
        ));
    }
    Ok(())
}

fn materialize_pmem_image(layout: &GptDiskLayout, directory: &Path) -> Result<PathBuf> {
    let layers: Vec<_> = layout.partitions.iter().map(|p| p.layer.clone()).collect();
    let mut full_layout = calculate_gpt_layout(&layers)?;
    let alignment_sectors = PMEM_NAMESPACE_ALIGNMENT / full_layout.lb_size;
    full_layout.total_sectors =
        full_layout.total_sectors.div_ceil(alignment_sectors) * alignment_sectors;
    let payload_size = full_layout
        .total_sectors
        .checked_mul(full_layout.lb_size)
        .context("EROFS PMEM GPT size overflow")?;
    let namespace_size = payload_size
        .checked_add(PMEM_NAMESPACE_ALIGNMENT)
        .context("EROFS PMEM namespace size overflow")?;
    let first = full_layout
        .partitions
        .first()
        .context("no EROFS partitions")?;
    let last = full_layout
        .partitions
        .last()
        .context("no EROFS partitions")?;
    let head_size = first.start_lba * full_layout.lb_size;
    let tail_offset = (last.end_lba + 1) * full_layout.lb_size;

    // The sparse template contains only GPT metadata; copy layer data just once.
    let mut metadata = tempfile::NamedTempFile::new_in(directory)?;
    generate_full_gpt_image(&full_layout, metadata.path())?;
    let mut image = tempfile::NamedTempFile::new_in(directory)?;
    image.as_file().set_len(namespace_size)?;
    image.seek(SeekFrom::Start(PMEM_PAGE_SIZE))?;
    image.write_all(&pmem_namespace_superblock(payload_size))?;
    image.seek(SeekFrom::Start(PMEM_NAMESPACE_ALIGNMENT))?;
    std::io::copy(&mut metadata.as_file_mut().take(head_size), &mut image)?;
    metadata.seek(SeekFrom::Start(tail_offset))?;
    image.seek(SeekFrom::Start(PMEM_NAMESPACE_ALIGNMENT + tail_offset))?;
    std::io::copy(&mut metadata, &mut image)?;

    for partition in &layout.partitions {
        let mut layer = fs::File::open(&partition.layer.path)?;
        let expected = partition
            .layer
            .size_sectors
            .checked_mul(layout.lb_size)
            .context("EROFS partition size overflow")?;
        if layer.metadata()?.len() != expected {
            return Err(anyhow!(
                "EROFS layer size changed or is not sector aligned: {}",
                partition.layer.path
            ));
        }
        image.seek(SeekFrom::Start(
            PMEM_NAMESPACE_ALIGNMENT
                + partition
                    .start_lba
                    .checked_mul(layout.lb_size)
                    .context("EROFS partition offset overflow")?,
        ))?;
        let copied = std::io::copy(&mut layer, &mut image)?;
        if copied != expected {
            return Err(anyhow!(
                "EROFS layer changed while copying: {}",
                partition.layer.path
            ));
        }
    }
    image.as_file().sync_all()?;
    // Drop materialization-warmed cache before QEMU maps the image.
    if let Err(error) = posix_fadvise(
        image.as_file(),
        0,
        0,
        PosixFadviseAdvice::POSIX_FADV_DONTNEED,
    ) {
        warn!(sl!(), "Failed to advise dropping EROFS PMEM image cache: {error}";
            "image" => image.path().display());
    }
    let path = directory.join(EROFS_PMEM_IMAGE);
    image.persist_noclobber(&path)?;
    Ok(path)
}

fn erofs_partition_options(partition: u32, pmem: bool) -> Vec<String> {
    let mut options = vec![
        "ro".to_string(),
        "X-kata.overlay-lower".to_string(),
        "X-kata.multi-layer=true".to_string(),
        "X-kata.gpt-partitioned=true".to_string(),
        format!("X-kata.partition-number={partition}"),
    ];
    if pmem {
        options.push("dax=always".to_string());
    }
    options
}

/// Maximum number of rootfs layer devices (erofs + rw layer) allowed in multi-layer EROFS mode.
/// This is a pre-flight sanity check before VMDK merging, to prevent excessive block devices
/// when many layers are used without fsmerge.
const MAX_ROOTFS_LAYER_DEVICES: usize = 129; // 128 EROFS layers + 1 rw layer (129 total)
/// Default runtime directory for generated multi-layer EROFS metadata.
pub(crate) const DEFAULT_KATA_GUEST_ROOT_SHARED_FS: &str = "/run/kata-containers/";
/// Template for mkdir option in overlay mount (X-containerd.mkdir.path)
const X_CONTAINERD_MKDIR_PATH: &str = "X-containerd.mkdir.path=";
/// Template for mkdir option passed to guest agent (X-kata.mkdir.path)
const X_KATA_MKDIR_PATH: &str = "X-kata.mkdir.path=";

/// Create the per-container directory under the shared filesystem root.
pub(crate) fn ensure_container_dir(sid: &str, cid: &str) -> Result<PathBuf> {
    let dir = PathBuf::from(kata_types::prefix_with_rootless_dir(
        DEFAULT_KATA_GUEST_ROOT_SHARED_FS,
    ))
    .join(sid)
    .join(cid);
    fs::create_dir_all(&dir).context(format!(
        "failed to create container directory: {}",
        dir.display()
    ))?;

    Ok(dir)
}

fn ensure_pmem_images_dir(base: &str, sid: &str, cid: &str) -> Result<PathBuf> {
    if base.is_empty() {
        return ensure_container_dir(sid, cid);
    }
    let dir = Path::new(base).join(sid).join(cid);
    fs::create_dir_all(&dir).with_context(|| {
        format!(
            "failed to create EROFS PMEM image directory: {}",
            dir.display()
        )
    })?;
    Ok(dir)
}

/// Generate a merged VMDK layout from multiple EROFS devices.
///
/// For a single device, the EROFS image is used directly without a VMDK
/// wrapper. For multiple devices, this returns a reserved descriptor path and
/// a structured layout but does not create a file at that path. The QEMU
/// backend serializes the layout after preparing its backing files.
///
/// And `erofs_devices` are for host paths to EROFS image files (from `source` and `device=` options)
async fn generate_merged_erofs_vmdk(
    sid: &str,
    cid: &str,
    erofs_devices: &[String],
) -> Result<(String, BlockSourceFormat)> {
    if erofs_devices.is_empty() {
        return Err(anyhow!("no EROFS devices provided"));
    }

    // Validate all device paths exist and are regular files before proceeding.
    for dev_path in erofs_devices {
        let metadata = fs::metadata(dev_path)
            .context(format!("EROFS device path not accessible: {}", dev_path))?;
        if !metadata.is_file() {
            return Err(anyhow!(
                "EROFS device path is not a regular file: {}",
                dev_path
            ));
        }
    }

    // For a single device, use it directly without a VMDK descriptor.
    if erofs_devices.len() == 1 {
        info!(
            sl!(),
            "single EROFS device, using directly: {}", erofs_devices[0]
        );
        return Ok((erofs_devices[0].clone(), BlockSourceFormat::Raw));
    }

    // This reserved path identifies the block device and is included in logs;
    // no descriptor file is created here. The QEMU backend serializes the
    // structured layout using its fdset transport.
    let container_dir = ensure_container_dir(sid, cid)?;
    let vmdk_path = container_dir.join(EROFS_MERGED_VMDK);

    info!(
        sl!(),
        "creating VMDK layout for {} EROFS devices: {}",
        erofs_devices.len(),
        vmdk_path.display()
    );

    let vmdk = create_vmdk_config(erofs_devices).context("failed to create VMDK layout")?;

    Ok((
        vmdk_path.display().to_string(),
        BlockSourceFormat::Vmdk(vmdk),
    ))
}

/// Create a VMDK layout for multiple EROFS extents (flatten device).
fn create_vmdk_config(erofs_paths: &[String]) -> Result<VmdkConfig> {
    if erofs_paths.is_empty() {
        return Err(anyhow!("empty EROFS path list, cannot create VMDK layout"));
    }

    struct ExtentInfo {
        path: String,
        total_sectors: u64,
    }

    let mut extents: Vec<ExtentInfo> = Vec::with_capacity(erofs_paths.len());
    let mut total_sectors: u64 = 0;

    for erofs_path in erofs_paths {
        let metadata = fs::metadata(erofs_path)
            .context(format!("failed to stat EROFS file: {}", erofs_path))?;

        let file_size = metadata.len();
        if file_size == 0 {
            warn!(sl!(), "EROFS file {} is zero-length, skipping", erofs_path);
            continue;
        }

        let sectors = file_size.div_ceil(512);

        if file_size % 512 != 0 {
            warn!(
                sl!(),
                "EROFS file {} size ({} bytes) is not 512-byte aligned, \
                 rounding up to {} sectors ({} bytes addressable)",
                erofs_path,
                file_size,
                sectors,
                sectors * 512
            );
        }

        total_sectors = total_sectors.checked_add(sectors).ok_or_else(|| {
            anyhow!(
                "total sector count overflow when adding {} ({} sectors)",
                erofs_path,
                sectors
            )
        })?;

        extents.push(ExtentInfo {
            path: erofs_path.clone(),
            total_sectors: sectors,
        });
    }

    if total_sectors == 0 {
        return Err(anyhow!(
            "no valid EROFS files to create VMDK layout (all files are empty)"
        ));
    }

    let mut vmdk = VmdkConfig::default();
    for extent in &extents {
        vmdk.push_extent_chunked(&extent.path, extent.total_sectors);
        info!(
            sl!(),
            "VMDK extent: {} ({} sectors)", extent.path, extent.total_sectors
        );
    }

    info!(
        sl!(),
        "VMDK layout created: total {} sectors, {} source extents",
        total_sectors,
        extents.len()
    );

    Ok(vmdk)
}

/// Generate a GPT-partitioned VMDK layout for per-partition storage creation.
///
/// Returns a reserved descriptor path, structured VMDK layout, GPT layout,
/// and generated metadata files. This function does not create a descriptor
/// file at that path; the QEMU backend serializes the layout using its fdset
/// transport.
fn generate_gpt_vmdk_with_layout(
    sid: &str,
    cid: &str,
    erofs_layers: Vec<ErofsLayer>,
) -> Result<(String, VmdkConfig, GptDiskLayout, GptMetadataFiles)> {
    if erofs_layers.is_empty() {
        return Err(anyhow!("no EROFS layers provided for GPT VMDK generation"));
    }

    // Validate all layer paths exist and are regular files
    for layer in &erofs_layers {
        let metadata = fs::metadata(&layer.path)
            .context(format!("EROFS layer path not accessible: {}", layer.path))?;
        if !metadata.is_file() {
            return Err(anyhow!(
                "EROFS layer path is not a regular file: {}",
                layer.path
            ));
        }
    }

    // Create container directory
    let container_dir = ensure_container_dir(sid, cid)?;
    let vmdk_path = container_dir.join(EROFS_MERGED_VMDK);

    info!(
        sl!(),
        "creating GPT-partitioned VMDK layout for {} EROFS layers: {}",
        erofs_layers.len(),
        vmdk_path.display()
    );

    // Generate GPT metadata files
    let (layout, mut gpt_files) = generate_gpt_metadata(sid, cid, erofs_layers, &container_dir)
        .context("failed to generate GPT metadata")?;

    let (vmdk, pad_paths) =
        create_gpt_vmdk_config(&layout, &gpt_files).context("failed to create GPT VMDK layout")?;
    gpt_files.pad_paths = pad_paths;

    Ok((vmdk_path.display().to_string(), vmdk, layout, gpt_files))
}

/// Create a structured VMDK layout for a GPT-partitioned disk.
///
/// Returns the list of generated padding file paths for cleanup tracking.
fn create_gpt_vmdk_config(
    layout: &GptDiskLayout,
    gpt_files: &GptMetadataFiles,
) -> Result<(VmdkConfig, Vec<PathBuf>)> {
    let mut vmdk = VmdkConfig::default();
    let mut pad_paths: Vec<PathBuf> = Vec::new();

    // 1. GPT head metadata
    vmdk.push_extent(
        &gpt_files.head_path.display().to_string(),
        gpt_files.head_sectors,
        0,
    );
    info!(
        sl!(),
        "VMDK extent: GPT head ({} sectors) at {}",
        gpt_files.head_sectors,
        gpt_files.head_path.display()
    );

    // 2. Layer extents with padding gaps
    // head ends at LBA 2047, so first gap starts at LBA 2048.
    let mut prev_end_lba = gpt_files.head_sectors - 1;

    let metadata_dir = gpt_files.head_path.parent().ok_or_else(|| {
        anyhow!(
            "GPT head file has no parent directory: {}",
            gpt_files.head_path.display()
        )
    })?;

    for (idx, part) in layout.partitions.iter().enumerate() {
        let gap_start_lba = prev_end_lba + 1;
        if part.start_lba > gap_start_lba {
            let gap_sectors = part.start_lba - gap_start_lba;
            let pad_path = metadata_dir.join(format!("pad-{}.img", idx));

            generate_padding_file(&pad_path, gap_sectors).context(format!(
                "failed to generate padding file: {}",
                pad_path.display()
            ))?;

            vmdk.push_extent(&pad_path.display().to_string(), gap_sectors, 0);
            pad_paths.push(pad_path);
        }

        vmdk.push_extent_chunked(&part.layer.path, part.layer.size_sectors);
        info!(
            sl!(),
            "VMDK extent: {} (partition {}, LBA {}-{}, {} sectors)",
            part.layer.path,
            part.partition_number,
            part.start_lba,
            part.end_lba,
            part.layer.size_sectors
        );

        prev_end_lba = part.end_lba;
    }

    info!(
        sl!(),
        "GPT VMDK layout created: total {} sectors, {} partitions",
        layout.total_sectors,
        layout.partitions.len()
    );

    if vmdk.total_sectors() != Some(layout.total_sectors) {
        return Err(anyhow!(
            "GPT VMDK extent size does not match disk layout: {:?} != {}",
            vmdk.total_sectors(),
            layout.total_sectors
        ));
    }

    Ok((vmdk, pad_paths))
}

async fn extract_block_device_info(
    device_info: &DeviceType,
    read_only: bool,
) -> Result<(agent::Storage, String)> {
    // storage
    let mut storage = agent::Storage {
        options: if read_only {
            vec!["ro".to_string()]
        } else {
            Vec::new()
        },
        ..Default::default()
    };
    let mut device_id = String::new();
    if let DeviceType::BlockModern(device_mod) = device_info.clone() {
        let device = device_mod.lock().await.clone();
        storage.driver = device.config.driver_option.clone();
        storage.source = agent_storage_source_from_block_config(&device.config)?;
        device_id = device.device_id;
    }

    Ok((storage, device_id))
}

/// EROFS Multi-Layer Rootfs with overlay support
///
/// Handles the EROFS Multi-Layer where rootfs consists of:
/// - Optional ext4 rw disk -> virtio-blk when host rw backing exists.
/// - EROFS layers (fsmeta + flattened layers) -> virtio-blk via VMDK.
/// - Overlay metadata that combines the writable upper with the EROFS lower.
pub(crate) struct ErofsMultiLayerRootfs {
    guest_path: String,
    device_ids: Vec<String>,
    // Writable layer storage (upper layer), typically ext4 and optional when
    // the agent creates a /run-backed upper.
    rwlayer_storage: Option<Storage>,
    // Read-only EROFS layer storages (lower layers), one per partition in GPT mode
    erofs_storages: Vec<Storage>,
    // Temporary host files used by VMDK-backed rootfs layouts (GPT
    // leading-metadata image, padding images, and descriptor), removed after
    // device teardown.
    cleanup_paths: Vec<PathBuf>,
    // Container-scoped runtime directory that may only contain generated helper artifacts.
    generated_artifacts_dir: PathBuf,
    // The PMEM image may live outside the runtime directory.
    pmem_image_path: Option<PathBuf>,
}

impl ErofsMultiLayerRootfs {
    fn cleanup_generated_files(&self) -> Result<()> {
        for path in &self.cleanup_paths {
            if !path.starts_with(&self.generated_artifacts_dir)
                && self.pmem_image_path.as_ref() != Some(path)
            {
                continue;
            }
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to remove file: {}", path.display()));
                }
            }
        }
        Ok(())
    }

    pub async fn new(
        device_manager: &RwLock<DeviceManager>,
        sid: &str,
        cid: &str,
        rootfs_mounts: &[Mount],
        _share_fs: &Option<Arc<dyn crate::share_fs::ShareFs>>,
    ) -> Result<Self> {
        let container_path = do_get_guest_path(ROOTFS, cid, false, false);
        let host_path = do_get_host_path(ROOTFS, sid, cid, false, false);

        fs::create_dir_all(&host_path)
            .map_err(|e| anyhow!("failed to create rootfs dir {}: {:?}", host_path, e))?;

        let mut device_ids = Vec::new();
        let mut rwlayer_storage: Option<Storage> = None;
        let mut erofs_storages: Vec<Storage> = Vec::new();
        let mut cleanup_paths: Vec<PathBuf> = Vec::new();
        let mut pmem_image_path = None;
        // Track whether GPT+VMDK erofs layers have already been processed in bulk.
        let mut gpt_erofs_processed = false;

        // Directories to create (X-containerd.mkdir.path)
        let mut mkdir_dirs: Vec<String> = Vec::new();

        let blkdev_info = get_block_device_info(device_manager).await;
        let block_driver = blkdev_info.block_device_driver.clone();
        let pmem = blkdev_info.experimental_erofs_pmem;
        if pmem {
            warn!(
                sl!(),
                "Experimental EROFS PMEM: guest dm-verity is disabled"
            );
            for mount in rootfs_mounts
                .iter()
                .filter(|m| m.fs_type.eq_ignore_ascii_case(EROFS_ROOTFS_TYPE))
            {
                validate_pmem_layer(mount).context("validate EROFS PMEM layer")?;
            }
        }

        // Check block device count limit
        let expected_device_count = rootfs_mounts
            .iter()
            .filter(|m| {
                m.fs_type.eq_ignore_ascii_case(RW_LAYER_ROOTFS_TYPE)
                    || m.fs_type.eq_ignore_ascii_case(EROFS_ROOTFS_TYPE)
            })
            .count();

        // TODO(Alex Lyn): fsmerge mode with single erofs mount and multiple device= options
        // may require multiple block devices if containerd does not merge layers into one file.
        // This is a fallback or default mode if fsmerge is not enabled.
        if expected_device_count > MAX_ROOTFS_LAYER_DEVICES {
            return Err(anyhow!(
                "exceeded maximum block devices for multi-layer EROFS: {} > {}",
                expected_device_count,
                MAX_ROOTFS_LAYER_DEVICES
            ));
        }

        // Pre-extract mkdir directives from overlay mounts before the main loop,
        // so they are available regardless of mount ordering.
        for mount in rootfs_mounts {
            if matches!(
                mount.fs_type.as_str(),
                "overlay" | "format/overlay" | "format/mkdir/overlay"
            ) {
                for opt in &mount.options {
                    if let Some(mkdir_spec) = opt.strip_prefix(X_CONTAINERD_MKDIR_PATH) {
                        mkdir_dirs.push(mkdir_spec.to_string());
                    }
                }
            }
        }

        // Process each mount in rootfs_mounts to set up devices and storages
        for mount in rootfs_mounts {
            match mount.fs_type.as_str() {
                fmt if fmt.eq_ignore_ascii_case(RW_LAYER_ROOTFS_TYPE) => {
                    // Mount[0]: rw layer -> virtio-blk device /dev/vdX1
                    info!(
                        sl!(),
                        "multi-layer erofs: adding rw layer: {}", mount.source
                    );

                    let device_config = &mut BlockConfigModern {
                        driver_option: block_driver.clone(),
                        path_on_host: mount.source.clone(),
                        blkdev_aio: BlockDeviceAio::new(&blkdev_info.block_device_aio),
                        num_queues: blkdev_info.num_queues,
                        queue_size: blkdev_info.queue_size,
                        ..Default::default()
                    };

                    let device_info = do_handle_device(
                        device_manager,
                        &DeviceConfig::BlockCfgModern(device_config.clone()),
                    )
                    .await
                    .context("failed to attach rw block device")?;

                    let (mut rwlayer, device_id) = extract_block_device_info(&device_info, false)
                        .await
                        .context("failed to get block device for rw layer")?;
                    info!(
                        sl!(),
                        "writable block device attached - device_id: {} guest_path: {}",
                        device_id,
                        rwlayer.source
                    );

                    // Filter out "loop" option which is not needed in VM (device is already /dev/vdX)
                    let mut options: Vec<String> = mount
                        .options
                        .iter()
                        .filter(|o| *o != "loop")
                        .cloned()
                        .collect();

                    // RW layer is the writable upper layer (marked with X-kata.overlay-upper)
                    options.push("X-kata.overlay-upper".to_string());
                    options.push("X-kata.multi-layer=true".to_string());

                    // Set up storage for rw layer (upper layer)
                    rwlayer.fs_type = RW_LAYER_ROOTFS_TYPE.to_string();
                    rwlayer.mount_point = container_path.clone();
                    rwlayer.options = options;

                    rwlayer_storage = Some(rwlayer);
                    device_ids.push(device_id);
                }
                fmt if fmt.eq_ignore_ascii_case(EROFS_ROOTFS_TYPE) => {
                    // Mount[1]: erofs layers -> virtio-blk via VMDK /dev/vdX2
                    //
                    // Two modes are supported:
                    // 1. fsmerge mode: Single erofs mount with `device=` options pointing to additional files.
                    //    This is used when containerd has already merged layers into a single file.
                    // 2. GPT+VMDK mode: Multiple independent erofs mounts (each mount is a separate layer file).
                    //    This is used when containerd does NOT use fsmerge, and we need to create GPT partitions.

                    // In GPT mode, all erofs layers are processed in bulk on the first
                    // encounter. Skip subsequent erofs mounts but continue iterating
                    // so that later ext4 rw-layer and overlay mounts are still handled.
                    if gpt_erofs_processed {
                        info!(
                            sl!(),
                            "multi-layer erofs: skipping already-processed erofs mount: {}",
                            mount.source
                        );
                        continue;
                    }

                    // Collect all EROFS mounts once with their original indices.
                    let erofs_mounts_indexed: Vec<(usize, &Mount)> = rootfs_mounts
                        .iter()
                        .enumerate()
                        .filter(|(_, m)| m.fs_type.eq_ignore_ascii_case(EROFS_ROOTFS_TYPE))
                        .collect();
                    let total_erofs_mounts = erofs_mounts_indexed.len();

                    // GPT+VMDK mode: Multiple independent erofs layer files
                    if total_erofs_mounts > 1 || pmem {
                        info!(
                            sl!(),
                            "multi-layer erofs: using GPT+VMDK mode for {} independent layers",
                            total_erofs_mounts
                        );

                        let mut erofs_layers = Vec::new();
                        // Map: layer source path -> original mount index (for dm-verity lookup)
                        let mut layer_source_to_mount_idx: HashMap<String, usize> = HashMap::new();

                        for (mount_idx, erofs_mount) in &erofs_mounts_indexed {
                            let layer_path = erofs_mount.source.clone();
                            let size_bytes = get_erofs_layer_size(&layer_path).context(format!(
                                "gptdisk: failed to get size of EROFS layer: {}",
                                layer_path
                            ))?;

                            if size_bytes == 0 {
                                warn!(
                                    sl!(),
                                    "gptdisk: EROFS layer {} is zero-length, skipping", layer_path
                                );
                                continue;
                            }

                            let size_sectors = size_bytes.div_ceil(512);
                            let snapshot_id = extract_snapshot_id(&layer_path);

                            layer_source_to_mount_idx.insert(layer_path.clone(), *mount_idx);
                            erofs_layers.push(ErofsLayer {
                                path: layer_path,
                                size_sectors,
                                snapshot_id,
                            });
                        }

                        if erofs_layers.is_empty() {
                            return Err(anyhow!(
                                "gptdisk: no valid EROFS layers found for GPT VMDK"
                            ));
                        }

                        // Generate GPT-partitioned VMDK and get layout information
                        let (erofs_path, vmdk, layout, gpt_files) =
                            generate_gpt_vmdk_with_layout(sid, cid, erofs_layers)
                                .context("gptdisk: failed to generate GPT VMDK")?;

                        // Track every generated file backing this VMDK for cleanup.
                        cleanup_paths.push(gpt_files.head_path.clone());
                        cleanup_paths.extend(gpt_files.pad_paths.iter().cloned());
                        for idx in 0..layout.partitions.len() {
                            if idx > 0 {
                                // Check for padding files (only created when there are gaps)
                                let pad_path = gpt_files
                                    .head_path
                                    .parent()
                                    .unwrap()
                                    .join(format!("pad-{}.img", idx));
                                if pad_path.exists() {
                                    cleanup_paths.push(pad_path);
                                }
                            }
                        }
                        // GPT assembly always produces a structured VMDK layout.
                        // `erofs_path` is its reserved descriptor path. QEMU leaves
                        // no file there, so cleanup is a no-op until a VMM
                        // materializes the descriptor.
                        cleanup_paths.push(PathBuf::from(&erofs_path));

                        info!(
                            sl!(),
                            "GPT VMDK layout created - id: {}, {} partitions",
                            erofs_path,
                            layout.partitions.len()
                        );

                        let (erofs_path, source, driver, layout) = if pmem {
                            let directory = ensure_pmem_images_dir(
                                &blkdev_info.experimental_erofs_pmem_images_path,
                                sid,
                                cid,
                            )?;
                            let (layout, path) = tokio::task::spawn_blocking(move || {
                                materialize_pmem_image(&layout, &directory)
                                    .map(|path| (layout, path))
                            })
                            .await
                            .context("join EROFS PMEM materialization")?
                            .context("materialize EROFS PMEM GPT image")?;
                            cleanup_paths.push(path.clone());
                            pmem_image_path = Some(path.clone());
                            (
                                path.display().to_string(),
                                BlockSourceFormat::Raw,
                                "virtio-pmem".to_string(),
                                layout,
                            )
                        } else {
                            (
                                erofs_path,
                                BlockSourceFormat::Vmdk(vmdk),
                                block_driver.clone(),
                                layout,
                            )
                        };
                        let device_config = &mut BlockConfigModern {
                            driver_option: driver,
                            source,
                            path_on_host: erofs_path,
                            is_readonly: true,
                            blkdev_aio: BlockDeviceAio::new(&blkdev_info.block_device_aio),
                            num_queues: blkdev_info.num_queues,
                            queue_size: blkdev_info.queue_size,
                            ..Default::default()
                        };

                        let attached = do_handle_device(
                            device_manager,
                            &DeviceConfig::BlockCfgModern(device_config.clone()),
                        )
                        .await;
                        if pmem && attached.is_err() {
                            for path in &cleanup_paths {
                                if path.exists() {
                                    if let Err(error) = fs::remove_file(path) {
                                        warn!(sl!(), "Failed to clean up EROFS PMEM attachment: {error}";
                                            "path" => path.display());
                                    }
                                }
                            }
                        }
                        let device_info = attached.context("failed to attach GPT image device")?;

                        let (base_device, device_id) =
                            extract_block_device_info(&device_info, true).await?;
                        info!(
                            sl!(),
                            "GPT VMDK device attached - device_id: {} guest_path: {}",
                            device_id,
                            &base_device.source
                        );

                        device_ids.push(device_id);

                        // Create a storage entry for each GPT partition.
                        //
                        // Ordering guarantee: partitions in `layout` follow the same
                        // order as `erofs_layers`, which was collected by iterating
                        // `rootfs_mounts`. We use source path as the key to look up
                        // the original mount (for dm-verity annotations), so even if
                        // the mount array is reordered in the future, the mapping
                        // remains correct.
                        for (idx, part) in layout.partitions.iter().enumerate() {
                            // Find the original mount by source path (not by index)
                            let original_mount_idx = layer_source_to_mount_idx
                                .get(&part.layer.path)
                                .ok_or_else(|| {
                                    anyhow!(
                                        "gptdisk: internal error — partition {} source path '{}' \
                                         not found in mount-to-layer map",
                                        idx,
                                        part.layer.path
                                    )
                                })?;
                            let original_mount = &rootfs_mounts[*original_mount_idx];

                            let mut rolayer = base_device.clone();
                            let mut options = erofs_partition_options(part.partition_number, pmem);

                            // Look up dm-verity annotation from the original mount
                            let options_map: HashMap<String, String> = original_mount
                                .options
                                .iter()
                                .filter_map(|opt| {
                                    opt.split_once('=')
                                        .map(|(k, v)| (k.to_string(), v.to_string()))
                                })
                                .collect();

                            if let Some(dmverity_path) =
                                extract_dmverity_annotation(&options_map).filter(|_| !pmem)
                            {
                                info!(
                                    sl!(),
                                    "Found dm-verity annotation for partition {} from {}",
                                    idx,
                                    dmverity_path
                                );

                                let metadata = parse_dmverity_metadata_file(dmverity_path)
                                    .context(format!(
                                    "failed to parse dm-verity metadata file {} for partition {}",
                                    dmverity_path, idx
                                ))?;

                                info!(
                                    sl!(),
                                    "Parsed dm-verity meta for partition {} roothash={}, hashoffset={}",
                                    idx,
                                    metadata.roothash,
                                    metadata.hashoffset
                                );

                                let dmverity_opts =
                                    generate_dmverity_options(&metadata, Some(&part.layer.path));
                                info!(
                                    sl!(),
                                    "Added dm-verity options to partition {}: {:?}",
                                    idx,
                                    dmverity_opts
                                );
                                options.extend(dmverity_opts);
                            }

                            rolayer.fs_type = EROFS_ROOTFS_TYPE.to_string();
                            rolayer.mount_point = container_path.clone();
                            rolayer.options = options;
                            rolayer.source = base_device.source.clone();

                            info!(
                                sl!(),
                                "Created storage for GPT partition {} (partition number {}, LBA {}-{})",
                                idx, part.partition_number, part.start_lba, part.end_lba
                            );

                            erofs_storages.push(rolayer);
                        }

                        // Mark GPT erofs as processed so subsequent erofs mounts
                        // in the loop are skipped, while still allowing ext4 and
                        // overlay mounts to be visited.
                        gpt_erofs_processed = true;
                    } else {
                        // fsmerge mode: Single erofs mount with device= options
                        info!(
                            sl!(),
                            "multi-layer erofs: using fsmerge mode for erofs layers: {}",
                            mount.source
                        );

                        // Collect all EROFS devices: source + `device=` options
                        let mut erofs_devices = vec![mount.source.clone()];
                        for opt in &mount.options {
                            if let Some(device_path) = opt.strip_prefix("device=") {
                                erofs_devices.push(device_path.to_string());
                            }
                        }

                        info!(sl!(), "EROFS devices count: {}", erofs_devices.len());

                        // Build a merged VMDK layout from all EROFS devices.
                        // Multiple devices use VMDK; a single device remains Raw.
                        let (erofs_path, source) =
                            generate_merged_erofs_vmdk(sid, cid, &erofs_devices)
                                .await
                                .context("failed to generate EROFS VMDK")?;

                        let is_vmdk = matches!(&source, BlockSourceFormat::Vmdk(_));

                        info!(
                            sl!(),
                            "EROFS block device config - path: {}, structured VMDK: {}",
                            erofs_path,
                            is_vmdk
                        );

                        // Only a multi-device result has a structured VMDK layout
                        // and reserves `erofs_path` for its descriptor. A
                        // single-device result is raw EROFS, whose source path must
                        // not be tracked as a generated temporary file.
                        if is_vmdk {
                            cleanup_paths.push(PathBuf::from(&erofs_path));
                        }

                        let device_config = &mut BlockConfigModern {
                            driver_option: block_driver.clone(),
                            source,
                            path_on_host: erofs_path,
                            is_readonly: true, // EROFS layers are read-only, must set to avoid "resize" lock errors
                            blkdev_aio: BlockDeviceAio::new(&blkdev_info.block_device_aio),
                            num_queues: blkdev_info.num_queues,
                            queue_size: blkdev_info.queue_size,
                            ..Default::default()
                        };

                        let device_info = do_handle_device(
                            device_manager,
                            &DeviceConfig::BlockCfgModern(device_config.clone()),
                        )
                        .await
                        .context("failed to attach erofs block device")?;

                        let (mut rolayer, device_id) =
                            extract_block_device_info(&device_info, true).await?;
                        info!(
                            sl!(),
                            "erofs device attached - device_id: {} guest_path: {}",
                            device_id,
                            &rolayer.source
                        );

                        let mut options: Vec<String> = mount
                            .options
                            .iter()
                            .filter(|o| {
                                // Filter out options that are not valid erofs mount parameters:
                                // 1. "loop" - not needed in VM, device is already /dev/vdX
                                // 2. "device=" prefix - used for VMDK generation only, not for mount
                                // 3. "X-kata." prefix - metadata markers for kata internals
                                *o != "loop"
                                    && !o.starts_with("device=")
                                    && !o.starts_with("X-kata.")
                            })
                            .cloned()
                            .collect();

                        // Erofs layers are read-only lower layers (marked with X-kata.overlay-lower)
                        options.push("X-kata.overlay-lower".to_string());
                        options.push("X-kata.multi-layer=true".to_string());

                        info!(
                            sl!(),
                            "erofs storage options filtered: {:?} -> {:?}", mount.options, options
                        );

                        rolayer.fs_type = EROFS_ROOTFS_TYPE.to_string();
                        rolayer.mount_point = container_path.clone();
                        rolayer.options = options;

                        erofs_storages.push(rolayer);
                        device_ids.push(device_id);
                    }
                }
                fmt if fmt.eq_ignore_ascii_case("overlay")
                    || fmt.eq_ignore_ascii_case("format/overlay")
                    || fmt.eq_ignore_ascii_case("format/mkdir/overlay") =>
                {
                    // Mount[2]: overlay to combine rwlayer (upper) + erofs (lower)
                    // mkdir directives already extracted before the main loop
                    info!(
                        sl!(),
                        "multi-layer erofs: overlay mount (mkdir directives pre-extracted)"
                    );
                }
                _ => {
                    info!(
                        sl!(),
                        "multi-layer erofs: ignoring unknown mount type: {}", mount.fs_type
                    );
                }
            }
        }

        if device_ids.is_empty() {
            return Err(anyhow!("no devices attached for multi-layer erofs rootfs"));
        }

        // Forward overlay mkdir hints on the EROFS Storage only. The guest agent scans
        // every multi-layer storage for X-kata.mkdir.path; attaching here avoids splitting
        // the same metadata across rwlayer vs erofs when an ext4 upper exists.
        let mkdir_options = mkdir_dirs
            .iter()
            .map(|dir| format!("{}{}", X_KATA_MKDIR_PATH, dir))
            .collect::<Vec<_>>();
        if let Some(erofs) = erofs_storages.first_mut() {
            erofs.options.extend(mkdir_options);
        }

        Ok(Self {
            guest_path: container_path,
            device_ids,
            rwlayer_storage,
            erofs_storages,
            cleanup_paths,
            generated_artifacts_dir: PathBuf::from(kata_types::prefix_with_rootless_dir(
                DEFAULT_KATA_GUEST_ROOT_SHARED_FS,
            ))
            .join(sid)
            .join(cid),
            pmem_image_path,
        })
    }
}

#[async_trait]
impl Rootfs for ErofsMultiLayerRootfs {
    async fn get_guest_rootfs_path(&self) -> Result<String> {
        Ok(self.guest_path.clone())
    }

    async fn get_rootfs_mount(&self) -> Result<Vec<oci::Mount>> {
        Ok(Vec::new()) // For multi-layer EROFS, the actual mount is handled by guest agent, so return empty here.
    }

    async fn get_storage(&self) -> Option<Vec<Storage>> {
        // Return all storages for multi-layer EROFS. The rw layer is optional;
        // when absent, the agent creates a /run-backed upper dir. In GPT mode,
        // each partition has its own EROFS storage entry.
        let mut storages = Vec::new();

        if let Some(rwlayer) = self.rwlayer_storage.clone() {
            storages.push(rwlayer);
        }

        // Add all EROFS layer storages (single storage in fsmerge mode, multiple in GPT mode)
        for erofs in &self.erofs_storages {
            storages.push(erofs.clone());
        }

        if storages.is_empty() {
            None
        } else {
            Some(storages)
        }
    }

    async fn get_device_ids(&self) -> Result<Vec<String>> {
        Ok(self.device_ids.clone())
    }

    async fn cleanup(&self, device_manager: &RwLock<DeviceManager>) -> Result<()> {
        let mut dm = device_manager.write().await;
        for device_id in &self.device_ids {
            dm.try_remove_device(device_id).await?;
        }

        self.cleanup_generated_files()
    }
}

fn overlay_like(fs_type: &str) -> bool {
    matches!(
        fs_type.to_ascii_lowercase().as_str(),
        "overlay" | "format/overlay" | "format/mkdir/overlay"
    )
}

/// Check if mounts represent a multi-layer EROFS rootfs.
///
/// Matches what the containerd erofs snapshotter sends for an active snapshot:
/// an EROFS lower layer plus an overlay mount. With host rw backing enabled,
/// the mount list also includes an ext4 `rwlayer.img`; with `default_size="0"`
/// it does not, and the agent creates the writable upper under `/run`.
///
/// This is only the coarse dispatcher check; `ErofsMultiLayerRootfs::new`
/// parses the optional rwlayer and overlay metadata.
pub fn is_erofs_multi_layer(rootfs_mounts: &[Mount]) -> bool {
    if rootfs_mounts.len() < 2 {
        return false;
    }

    let has_erofs = rootfs_mounts
        .iter()
        .any(|m| m.fs_type.eq_ignore_ascii_case(EROFS_ROOTFS_TYPE));

    if !has_erofs {
        return false;
    }

    rootfs_mounts.iter().any(|m| overlay_like(&m.fs_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kata_types::mount::Mount;
    use std::convert::TryInto;
    use std::path::PathBuf;

    fn mount(fs_type: &str, options: &[&str]) -> Mount {
        Mount {
            fs_type: fs_type.to_string(),
            options: options.iter().map(|s| (*s).to_string()).collect(),
            destination: PathBuf::from("/"),
            ..Default::default()
        }
    }

    #[test]
    fn pmem_image_contains_layers_and_both_gpt_headers() {
        let dir = tempfile::tempdir().unwrap();
        let layers = [4096, 12288]
            .iter()
            .enumerate()
            .map(|(index, size)| {
                let path = dir.path().join(format!("layer-{index}.erofs"));
                fs::write(&path, vec![index as u8 + 1; *size]).unwrap();
                ErofsLayer {
                    path: path.display().to_string(),
                    size_sectors: (*size / 512) as u64,
                    snapshot_id: index.to_string(),
                }
            })
            .collect::<Vec<_>>();
        let (layout, _) =
            generate_gpt_metadata("sandbox", "container", layers, dir.path()).unwrap();
        let path = materialize_pmem_image(&layout, dir.path()).unwrap();
        let disk = fs::read(&path).unwrap();
        let payload = PMEM_NAMESPACE_ALIGNMENT as usize;
        assert_eq!(disk.len() % payload, 0);
        assert_eq!(&disk[4096..4112], b"NVDIMM_PFN_INFO\0");
        assert_eq!(
            u64::from_le_bytes(disk[4152..4160].try_into().unwrap()),
            PMEM_NAMESPACE_ALIGNMENT
        );
        assert_eq!(
            u64::from_le_bytes(disk[4160..4168].try_into().unwrap()),
            ((disk.len() - payload) / 4096) as u64
        );
        assert_eq!(u32::from_le_bytes(disk[4168..4172].try_into().unwrap()), 1);
        assert_eq!(&disk[payload + 512..payload + 520], b"EFI PART");
        assert_eq!(&disk[disk.len() - 512..disk.len() - 504], b"EFI PART");
        for (index, partition) in layout.partitions.iter().enumerate() {
            let start = payload + (partition.start_lba * 512) as usize;
            let size = (partition.layer.size_sectors * 512) as usize;
            assert_eq!(&disk[start..start + size], vec![index as u8 + 1; size]);
            let entry = payload + 1024 + index * 128;
            assert_eq!(
                u64::from_le_bytes(disk[entry + 32..entry + 40].try_into().unwrap()),
                partition.start_lba
            );
            assert_eq!(
                u64::from_le_bytes(disk[entry + 40..entry + 48].try_into().unwrap()),
                partition.end_lba
            );
        }
        // A second creation must not overwrite an image potentially still mapped by QEMU.
        assert!(materialize_pmem_image(&layout, dir.path()).is_err());
        assert_eq!(fs::read(path).unwrap(), disk);
    }

    #[test]
    fn pmem_images_use_configured_directory_and_cleanup_only_owned_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("images");
        let image_dir =
            ensure_pmem_images_dir(base.to_str().unwrap(), "sandbox", "container").unwrap();
        let other_dir = ensure_pmem_images_dir(base.to_str().unwrap(), "sandbox", "other").unwrap();
        let layer = dir.path().join("layer.erofs");
        fs::write(&layer, vec![1; 4096]).unwrap();
        let layout = calculate_gpt_layout(&[ErofsLayer {
            path: layer.display().to_string(),
            size_sectors: 8,
            snapshot_id: "1".to_string(),
        }])
        .unwrap();
        let image = materialize_pmem_image(&layout, &image_dir).unwrap();
        let other_image = materialize_pmem_image(&layout, &other_dir).unwrap();
        assert_eq!(image, base.join("sandbox/container/erofs-pmem.raw"));
        let runtime_dir = dir.path().join("runtime");
        fs::create_dir(&runtime_dir).unwrap();
        let metadata = runtime_dir.join("gpt_meta_head.img");
        fs::write(&metadata, b"metadata").unwrap();
        let rootfs = ErofsMultiLayerRootfs {
            guest_path: String::new(),
            device_ids: Vec::new(),
            rwlayer_storage: None,
            erofs_storages: Vec::new(),
            cleanup_paths: vec![image.clone(), metadata.clone(), other_image.clone()],
            generated_artifacts_dir: runtime_dir,
            pmem_image_path: Some(image.clone()),
        };
        rootfs.cleanup_generated_files().unwrap();
        rootfs.cleanup_generated_files().unwrap();
        assert!(!image.exists());
        assert!(!metadata.exists());
        assert!(other_image.exists());
        assert!(layer.exists());
    }

    #[test]
    fn pmem_images_directory_errors_do_not_fall_back_to_runtime_directory() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(
            ensure_pmem_images_dir(file.path().to_str().unwrap(), "sandbox", "container")
                .unwrap_err()
                .to_string()
                .contains("failed to create EROFS PMEM image directory")
        );
    }

    #[test]
    fn pmem_image_rejects_changed_layers_without_publishing_an_image() {
        let dir = tempfile::tempdir().unwrap();
        let layer = dir.path().join("layer.erofs");
        fs::write(&layer, vec![1; 4096]).unwrap();
        let layout = calculate_gpt_layout(&[ErofsLayer {
            path: layer.display().to_string(),
            size_sectors: 16,
            snapshot_id: "1".to_string(),
        }])
        .unwrap();
        assert!(materialize_pmem_image(&layout, dir.path()).is_err());
        assert!(!dir.path().join(EROFS_PMEM_IMAGE).exists());
    }

    #[test]
    fn pmem_layer_validation_rejects_compression_and_external_devices() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 4096];
        data[1024..1028].copy_from_slice(&[0xe2, 0xe1, 0xf5, 0xe0]);
        data[1036] = 12;
        file.write_all(&data).unwrap();
        let mut layer = mount("erofs", &[]);
        layer.source = file.path().display().to_string();
        validate_pmem_layer(&layer).unwrap();
        for (offset, value) in [(12, 9), (80, 2), (84, 1), (86, 1)] {
            let mut invalid = data.clone();
            invalid[1024 + offset] = value;
            fs::write(file.path(), invalid).unwrap();
            assert!(validate_pmem_layer(&layer).is_err());
        }
        fs::write(file.path(), data).unwrap();
        layer.options.push("device=/another-layer".to_string());
        assert!(validate_pmem_layer(&layer).is_err());
    }

    #[test]
    fn pmem_partition_options_request_dax_without_verity() {
        let options = erofs_partition_options(2, true);
        assert!(options.iter().any(|o| o == "dax=always"));
        assert!(options.iter().any(|o| o == "X-kata.partition-number=2"));
        assert!(!options.iter().any(|o| o.contains("dmverity")));
        assert!(!erofs_partition_options(2, false)
            .iter()
            .any(|o| o.starts_with("dax")));
    }

    #[test]
    fn is_erofs_multi_layer_rejects_short_list() {
        assert!(!is_erofs_multi_layer(&[]));
        assert!(!is_erofs_multi_layer(&[mount(EROFS_ROOTFS_TYPE, &[])]));
    }

    #[test]
    fn is_erofs_multi_layer_requires_erofs() {
        let mounts = vec![mount(RW_LAYER_ROOTFS_TYPE, &["rw"]), mount("overlay", &[])];
        assert!(!is_erofs_multi_layer(&mounts));
    }

    #[test]
    fn is_erofs_multi_layer_ext4_rw_erofs_and_overlay() {
        let mounts = vec![
            mount(RW_LAYER_ROOTFS_TYPE, &["rw"]),
            mount(EROFS_ROOTFS_TYPE, &[]),
            mount("overlay", &[]),
        ];
        assert!(is_erofs_multi_layer(&mounts));
    }

    #[test]
    fn is_erofs_multi_layer_implicit_upper_erofs_and_overlay_variants() {
        for overlay_type in ["overlay", "format/overlay", "format/mkdir/overlay"] {
            let mounts = vec![mount(EROFS_ROOTFS_TYPE, &[]), mount(overlay_type, &[])];
            assert!(
                is_erofs_multi_layer(&mounts),
                "expected multi-layer for overlay type {}",
                overlay_type
            );
        }
    }

    #[test]
    fn is_erofs_multi_layer_erofs_without_overlay_or_rw_is_false() {
        let mounts = vec![mount(EROFS_ROOTFS_TYPE, &[]), mount("btrfs", &[])];
        assert!(!is_erofs_multi_layer(&mounts));
    }

    #[test]
    fn is_erofs_multi_layer_does_not_validate_optional_rwlayer_options() {
        // The dispatcher only requires EROFS + overlay. Detailed rwlayer
        // interpretation is handled by ErofsMultiLayerRootfs::new.
        let mounts = vec![
            mount(RW_LAYER_ROOTFS_TYPE, &["ro"]),
            mount(EROFS_ROOTFS_TYPE, &[]),
            mount("overlay", &[]),
        ];
        assert!(is_erofs_multi_layer(&mounts));
    }
}
