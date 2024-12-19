use anyhow::{anyhow, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use containerd_client::{services::v1::ReadContentRequest, tonic::Request, with_namespace, Client};
use containerd_snapshots::{api, Info, Kind, Snapshotter, Usage};
use log::{debug, error, info, trace};
use nix::mount::MsFlags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::{
    collections::HashMap, fs, fs::File, fs::OpenOptions, io, io::Read, io::Seek,
    os::unix::ffi::OsStrExt, process::Command,
};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tonic::Status;
use uuid::Uuid;
use zerocopy::AsBytes;

const ROOT_HASH_LABEL: &str = "io.katacontainers.dm-verity.root-hash";
const TARGET_LAYER_DIGEST_LABEL: &str = "containerd.io/snapshot/cri.layer-digest";

#[derive(Serialize, Deserialize)]
struct ImageInfo {
    name: String,
    layers: Vec<LayerInfo>,
}

#[derive(Serialize, Deserialize)]
struct LayerInfo {
    digest: String,
    root_hash: String,
    signature: String,
    salt: String,
}

#[derive(PartialEq)]
struct LayerInfoInternal {
    salt: String,
    signature: Vec<u8>,
}

struct Store {
    root: PathBuf,
    signatures: Option<HashMap<String, LayerInfoInternal>>, // root_hash to info
    salts: Option<HashMap<String, Vec<u8>>>,                // digest to salt
}

const SIGNATURE_STORE: &str = "/var/lib/containerd/io.containerd.snapshotter.v1.tardev/signatures";

impl Store {
    fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            signatures: None,
            salts: None,
        }
    }

    fn lazy_read_signatures(&mut self) -> Result<()> {
        if self.signatures == None {
            info!("Loading signatures");
            self.read_signatures()
                .context("Failed to read signatures")?;
        }

        Ok(())
    }

    fn read_signatures(&mut self) -> Result<()> {
        let paths = std::fs::read_dir(Path::new(SIGNATURE_STORE))?;
        let mut signatures = HashMap::new();
        let mut salts = HashMap::new();
        for signatures_json_path in paths {
            let signatures_json = std::fs::read_to_string(signatures_json_path?.path())?;
            let image_info_list = serde_json::from_str::<Vec<ImageInfo>>(signatures_json.as_str())?;
            for image_info in image_info_list {
                for layer_info in image_info.layers {
                    signatures.insert(
                        layer_info.root_hash,
                        LayerInfoInternal {
                            signature: BASE64_STANDARD
                                .decode(layer_info.signature)
                                .context("Failed to decode signature")?,
                            salt: layer_info.salt.clone(),
                        },
                    );
                    salts.insert(
                        layer_info.digest,
                        hex::decode(layer_info.salt).context("Failed to decode salt")?,
                    );
                }
            }
        }

        self.signatures = Some(signatures);
        self.salts = Some(salts);

        Ok(())
    }

    /// Creates the name of the directory that containerd can use to extract a layer into.
    fn extract_dir(&self, name: &str) -> PathBuf {
        self.root.join("staging").join(name_to_hash(name))
    }

    /// Creates a directory that containerd can use to extract a layer into.
    ///
    /// It's a temporary directory that will be thrown away by the snapshotter.
    fn extract_dir_to_write(&self, name: &str) -> io::Result<PathBuf> {
        let path = self.extract_dir(name);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Creates a temporary staging directory for layers.
    fn staging_dir(&self) -> io::Result<tempfile::TempDir> {
        let path = self.root.join("staging");
        fs::create_dir_all(&path)?;
        tempfile::tempdir_in(path)
    }

    /// Creates the snapshot file path from its name.
    ///
    /// If `write` is `true`, it also ensures that the directory exists.
    fn snapshot_path(&self, name: &str, write: bool) -> Result<PathBuf, Status> {
        let path = self.root.join("snapshots").join(name_to_hash(name));
        if write {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        }

        Ok(path)
    }

    /// Creates the layer file path from its name.
    fn layer_path(&self, name: &str) -> PathBuf {
        self.root.join("layers").join(name_to_hash(name))
    }

    /// Creates the layer file path from its name and ensures that the directory exists.
    fn layer_path_to_write(&self, name: &str) -> Result<PathBuf, Status> {
        let path = self.layer_path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(path)
    }

    /// Reads the information from storage for the given snapshot name.
    fn read_snapshot(&self, name: &str) -> Result<Info, Status> {
        let path = self.snapshot_path(name, false)?;
        let file = fs::File::open(&path).map_err(|e| {
            Status::unknown(format!(
                "unable to open snapshot ('{}'): {e}",
                path.display()
            ))
        })?;
        serde_json::from_reader(file)
            .map_err(|_| Status::unknown(format!("unable to read snapshot ('{}')", path.display())))
    }

    /// Writes to storage the given snapshot information.
    ///
    /// It fails if a snapshot with the given name already exists.
    fn write_snapshot(
        &mut self,
        kind: Kind,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<(), Status> {
        let info = Info {
            kind,
            name: key,
            parent,
            labels,
            ..Info::default()
        };
        let name = self.snapshot_path(&info.name, true)?;
        // TODO: How to specify the file mode (e.g., 0600)?
        let file = OpenOptions::new().write(true).create_new(true).open(name)?;
        let foo = serde_json::to_writer_pretty(file, &info)
            .map_err(|_| Status::internal("unable to write snapshot"));
        foo?;
        Ok(())
    }

    fn get_salt(&self, digest: &str) -> Result<Vec<u8>> {
        self.salts
            .as_ref()
            .context("salts not loaded")?
            .get(digest)
            .context("missing signature for the requested layer")
            .cloned()
    }

    fn load_signature(&self, hash: &str) -> Result<(String, String)> {
        let signature_name = format!("verity:{hash}");

        let (signature, salt) = match &self.signatures {
            None => panic!("signatures were not loaded"),
            Some(signatures) => match signatures.get(hash) {
                Some(layer_info) => (&layer_info.signature, layer_info.salt.clone()),
                None => return Err(anyhow::anyhow!("missing signature for root hash {hash}")),
            },
        };

        // https://lkml.org/lkml/2019/7/17/762
        // https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html
        let keyctl = Command::new("keyctl")
            .stdin(Stdio::piped())
            .arg("padd")
            .arg("user")
            .arg(&signature_name)
            .arg("@s")
            .spawn()?;
        keyctl.stdin.as_ref().unwrap().write_all(&signature)?; // TODO do not unwrap
                                                               // write!(keyctl.stdin.as_ref().unwrap(), "{}", signature)?; // TODO do not unwrap
        let output = keyctl.wait_with_output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("failed to load signature"));
        }

        Ok((signature_name, salt))
    }

    /// Creates a new snapshot for use.
    ///
    /// It checks that the parent chain exists and that all ancestors are committed and consist of
    /// layers before writing the new snapshot.
    fn prepare_snapshot_for_use(
        &mut self,
        kind: Kind,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Status> {
        if let Err(e) = self.lazy_read_signatures() {
            error!("Failing to read signatures: {e}");
            return Err(Status::internal(format!(
                "Failed to read signatures: {:?}",
                e
            )));
        }
        let mounts = self.mounts_from_snapshot(&parent, false)?;
        self.write_snapshot(kind, key, parent, labels)?;
        Ok(mounts)
    }

    // ported over from kata agent
    // prepares a dm-verity target configuration by reading metadata from a file (block/loop device)
    // and returning the parameters required to set up the device-mapper verity target
    fn prepare_dm_target(
        &self,
        path: &str,
        hash: &str,
        signature_name: &str,
        salt: &String,
    ) -> Result<(u64, u64, String, String)> {
        info!("prepare_dm_target for loop device");
        let mut file = File::open(path)?;
        let size = file.seek(std::io::SeekFrom::End(0))?;
        if size < 4096 {
            return Err(anyhow!("loop device ({path}) is too small: {size}"));
        }

        // last 4096 bytes of loop device is superblock
        file.seek(std::io::SeekFrom::End(-4096))?;
        let mut buf = [0u8; 4096];
        file.read_exact(&mut buf)?;

        // parse super block
        let mut sb = verity::SuperBlock::default();
        sb.as_bytes_mut()
            .copy_from_slice(&buf[4096 - 512..][..std::mem::size_of::<verity::SuperBlock>()]);
        let data_block_size = u64::from(sb.data_block_size.get());
        let hash_block_size = u64::from(sb.hash_block_size.get());
        let data_size = sb
            .data_block_count
            .get()
            .checked_mul(data_block_size)
            .ok_or_else(|| anyhow!("Invalid data size"))?;
        if data_size > size {
            return Err(anyhow!(
                "Data size ({data_size}) is greater than device size ({size}) for device {path}"
            ));
        }

        // generate dm-verity table, use all zero salt
        // TODO: Store other parameters in super block: version, hash type,
        // salt.
        let construction_parameters = format!(
                "1 {path} {path} {data_block_size} {hash_block_size} {} {} sha256 {hash} {salt} 2 root_hash_sig_key_desc {signature_name}",
                data_size / data_block_size,
                (data_size + hash_block_size - 1) / hash_block_size,
            );
        trace!("dm-verity construction params: {construction_parameters}");
        Ok((0, data_size / 512, "verity".into(), construction_parameters))
    }

    // Creates dm-verity device for a given layer file
    fn create_dm_verity_device(&self, layer_path: &str, root_hash: &str) -> Result<String> {
        let dm = devicemapper::DM::new()?;
        let layer_name = Path::new(layer_path)
            .file_name()
            .ok_or_else(|| anyhow!("Unable to get file name from layer path"))?
            .to_str()
            .ok_or_else(|| anyhow!("Unable to convert file name to UTF-8 string"))?;
        info!("create_dm_verity_device for layer: {}", layer_name);

        let name = devicemapper::DmName::new(&layer_name)?;
        let opts = devicemapper::DmOptions::default().set_flags(devicemapper::DmFlags::DM_READONLY);

        if let Err(e) = dm.device_create(name, None, opts) {
            info!("Failed to create Device Mapper device: {:?}", e);
            return Err(e.into());
        }
        let id = devicemapper::DevId::Name(name);

        let result = (|| {
            // Step 1: Set up loop device for the given layer_path
            let setup_output = Command::new("losetup")
                .arg("-fP")
                .arg(layer_path)
                .output()
                .expect("Failed to execute losetup command to create loop device");

            if !setup_output.status.success() {
                info!(
                    "Failed to set up loop device: {:?}",
                    String::from_utf8_lossy(&setup_output.stderr)
                );
                return Err(anyhow::anyhow!(
                    "Failed to set up loop device: {:?}",
                    String::from_utf8_lossy(&setup_output.stderr)
                ));
            }
            info!("set up loop device");

            // Step 2: Find the loop device associated with the file
            let loop_output = Command::new("losetup")
                .arg("-a")
                .output()
                .expect("Failed to list loop devices");

            let loop_output_str = String::from_utf8_lossy(&loop_output.stdout);
            let loop_device = loop_output_str
                .lines()
                .find(|line| line.contains(layer_path))
                .and_then(|line| line.split(":").next())
                .ok_or_else(|| anyhow::anyhow!("Could not find loop device for {}", layer_path))?;

            info!("selected newly created loop device: {}", loop_device);

            // Use the loop device path for DM-Verity
            let device_path = loop_device;

            let (signature_name, salt) = self.load_signature(root_hash)?;

            // Step 3: Prepare DM-Verity target
            let target = self.prepare_dm_target(device_path, root_hash, &signature_name, &salt)?;

            // Step 4: Load the DM table for DM-Verity
            dm.table_load(&id, &[target], opts)
                .context("Unable to load DM-Verity table")?;
            info!("loaded DM table for DM-Verity");

            // Step 5: Suspend the DM device to make it active
            dm.device_suspend(&id, opts)
                .context("Unable to suspend DM device")?;
            info!("suspended DM device for activation");

            // Step 6: Return success, with the path of the DM-Verity device
            Ok(format!("/dev/mapper/{}", layer_name))
        })();

        // If there is an error, remove the DM device and clean up the loop device
        result.map_err(|e| {
            // Remove the DM device if it was created
            if let Err(remove_err) = dm.device_remove(&id, devicemapper::DmOptions::default()) {
                info!(
                    "Unable to remove DM device ({}): {:?}",
                    layer_name, remove_err
                );
            }

            // Clean up the loop device
            info!("Cleaning up loop device: {}", layer_path);
            let detach_output = Command::new("losetup")
                .arg("-d")
                .arg(layer_path)
                .output()
                .expect("Failed to execute losetup detach command");

            if !detach_output.status.success() {
                info!(
                    "Failed to detach loop device: {:?}",
                    String::from_utf8_lossy(&detach_output.stderr)
                );
            } else {
                info!("Successfully detached loop device: {}", layer_path);
            }

            info!("Error occurred during DM-Verity setup: {:?}", e);
            e
        })
    }

    /// Mounts a DM-Verity device to a specified path.
    fn mount_dm_verity_device(
        &self,
        source: &str,
        target: &str,
        fstype: &str,
        options: &str,
        flags: MsFlags,
    ) -> Result<()> {
        if source.is_empty() {
            return Err(anyhow!("Source path for mounting cannot be empty."));
        }
        if target.is_empty() {
            return Err(anyhow!("Target path for mounting cannot be empty."));
        }
        if fstype.is_empty() {
            return Err(anyhow!("Filesystem type cannot be empty."));
        }

        let source_path = Path::new(source);
        let target_path = Path::new(target);

        // Ensure the target directory exists
        if !target_path.exists() {
            fs::create_dir_all(target_path)
                .with_context(|| format!("Failed to create mount point: {}", target))?;
        }

        // Attempt the mount operation
        nix::mount::mount(
            Some(source_path),
            target_path,
            Some(fstype),
            flags,
            Some(options),
        )
        .map_err(|e| anyhow!("Failed to mount {} to {} with error: {}", source, target, e))?;

        Ok(())
    }

    fn mounts_from_snapshot(
        &self,
        parent: &str,
        do_mount: bool,
    ) -> Result<Vec<api::types::Mount>, Status> {
        const PREFIX: &str = "io.katacontainers.fs-opt";

        // Get chain of layers.
        let mut next_parent = Some(parent.to_string());
        let mut layers = Vec::new();
        let mut opts = vec![format!(
            "{PREFIX}.layer-src-prefix={}",
            self.root.join("layers").to_string_lossy()
        )];
        let src_prefix = self.root.join("layers");
        let mut mounted_layers = Vec::new();
        while let Some(p) = next_parent {
            let infor = self.read_snapshot(&p);
            let info = match infor {
                Ok(a) => a,
                Err(b) => {
                    error!("failed to read snapshot: {}", b);
                    return Err(b);
                }
            };
            if info.kind != Kind::Committed {
                return Err(Status::failed_precondition(
                    "parent snapshot is not committed",
                ));
            }

            let root_hash = if let Some(rh) = info.labels.get(ROOT_HASH_LABEL) {
                rh
            } else {
                return Err(Status::failed_precondition(
                    "parent snapshot has no root hash stored",
                ));
            };

            let name = name_to_hash(&p);
            let layer_info = format!(
                "{name},tar,ro,{PREFIX}.block_device=file,{PREFIX}.is-layer,{PREFIX}.root-hash={root_hash}");
            info!(
                "mounts_from_snapshot(): processing snapshots: {}, layername: {}",
                &info.name, &name
            );

            if do_mount {
                info!("mounts_from_snapshot(): performing tarfs mounting via dm-verity");
                // Extract layer information
                let mut fields = layer_info.split(',');
                let src = if let Some(p) = fields.next() {
                    if !p.is_empty() && p.as_bytes()[0] != b'/' {
                        src_prefix.join(Path::new(p))
                    } else {
                        Path::new(p).to_path_buf()
                    }
                } else {
                    return Err(Status::invalid_argument(
                        "Missing source path in layer info",
                    ));
                };
                info!("src: {}", src.display());

                let fs_type = fields.next().ok_or_else(|| {
                    Status::invalid_argument("Missing filesystem type in layer info")
                })?;
                info!("fs_type: {}", fs_type);

                let fs_opts = fields
                    .filter(|o| !o.starts_with("io.katacontainers."))
                    .fold(String::new(), |a, b| {
                        if a.is_empty() {
                            b.into()
                        } else {
                            format!("{a},{b}")
                        }
                    });
                info!("fs_opts: {}", fs_opts);

                let mount_path = self.root.join("mounts").join(&name);
                info!("mount_path: {}", mount_path.display());
                std::fs::create_dir_all(&mount_path)?;

                // Step 0: Check if the dm-verity device already exists
                let dm_verity_device = format!("/dev/mapper/{}", name);
                if Path::new(&dm_verity_device).exists() {
                    info!(
                        "dm-verity device already exists for layer {}: {}",
                        name, dm_verity_device
                    );
                } else {
                    // Step 1:  Create a dm-verity device for the tarfs layer
                    let created_dm_verity_device = self
                        .create_dm_verity_device(src.to_str().unwrap(), root_hash)
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to create dm-verity device for source {:?}: {:?}",
                                src, e
                            ))
                        })?;
                    info!(
                        "created dm-verity device for layer {}: {}",
                        name, created_dm_verity_device
                    );
                }

                // Step 2: Check if the mount path is already mounted
                let mount_status = Command::new("mountpoint")
                    .arg("-q")
                    .arg(&mount_path)
                    .status()?;
                if mount_status.success() {
                    info!(
                        "Mount path {:?} is already mounted, skipping mounting.",
                        mount_path
                    );
                } else {
                    // Mount the dm-verity device to the mount path
                    let flags = MsFlags::MS_RDONLY; // Read-only to ensure integrity
                    self.mount_dm_verity_device(
                        &dm_verity_device,
                        mount_path.to_str().unwrap(),
                        fs_type,
                        &fs_opts,
                        flags,
                    )
                    .map_err(|e| {
                        Status::internal(format!(
                            "Failed to mount dm-verity device {} to {:?}: {:?}",
                            dm_verity_device, mount_path, e
                        ))
                    })?;
                    info!(
                        "mounted single layer dm-verity device {} to {:?}",
                        dm_verity_device, mount_path
                    );
                }

                mounted_layers.push(mount_path.clone());
            }

            layers.push(name);

            opts.push(format!(
                "{PREFIX}.layer={}",
                BASE64_STANDARD.encode(layer_info.as_bytes())
            ));

            next_parent = (!info.parent.is_empty()).then_some(info.parent);
        }

        if do_mount {
            info!("mounts_from_snapshot(): perform overlay mounting");
            let overlay_root = self.root.join("overlay").join(Uuid::new_v4().to_string());
            let overlay_target = overlay_root.join("mount");
            let overlay_upper = overlay_root.join("upper");
            let overlay_work = overlay_root.join("work");

            std::fs::create_dir_all(&overlay_upper)?;
            std::fs::create_dir_all(&overlay_work)?;
            std::fs::create_dir_all(&overlay_target)?;
            fs::set_permissions(&overlay_upper, fs::Permissions::from_mode(0o755))?;
            fs::set_permissions(&overlay_work, fs::Permissions::from_mode(0o755))?;

            // Prepare the list of lowerdirs from mounted dm-verity layers
            let lowerdirs = mounted_layers
                .iter()
                .map(|layer| layer.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(":");
            info!(
                "Combining dm-verity layers into overlay lowerdirs: {}",
                lowerdirs
            );

            // DEBUG: Validate that lowerdirs does not exceed PATH_MAX
            info!("Lowerdirs string len: {}", lowerdirs.len());
            if lowerdirs.len() > 4096 {
                return Err(Status::internal(format!(
                    "Lowerdirs string exceeds allowable length: {}",
                    lowerdirs.len()
                )));
            }

            // Perform an overlay mount
            trace!(
                "mount none {} -t overlay -o lowerdir={lowerdirs},upperdir={},workdir={}",
                overlay_target.to_string_lossy(),
                overlay_upper.to_string_lossy(),
                overlay_work.to_string_lossy()
            );

            let status = Command::new("mount")
                .arg("none")
                .arg(&overlay_target)
                .args(&[
                    "-t",
                    "overlay",
                    "-o",
                    &format!(
                        "lowerdir={},upperdir={},workdir={}",
                        lowerdirs,
                        overlay_upper.to_string_lossy(),
                        overlay_work.to_string_lossy()
                    ),
                ])
                .status()?;
            if !status.success() {
                return Err(Status::internal(format!(
                    "Failed to perform overlay mount at {:?}",
                    overlay_target
                )));
            }
            info!("Overlay mount completed at {:?}", overlay_target);

            // Clean up dm-verity and loop devices
            /*for layer_path in &mounted_layers {
                // Unmount dm-verity device
                info!("unmounting dm-verity layer at {:?}", layer_path);
                let status = Command::new("umount").arg(layer_path).status()?;
                if !status.success() {
                    error!("Failed to unmount dm-verity layer at {:?}, status: {status}", layer_path);
                } else {
                    info!("Successfully unmounted dm-verity layer at {:?}", layer_path);
                    // Remove dm-verity device
                    let dm_name = Path::new(layer_path)
                        .file_name()
                        .and_then(|f| f.to_str())
                        .ok_or_else(|| tonic::Status::internal(format!("Invalid dm-verity device path: {:?}", layer_path)))?;
                    let status = Command::new("dmsetup").arg("remove").arg(dm_name).status()?;
                    if !status.success() {
                        error!("Failed to remove dm-verity device: {}", dm_name);
                    } else {
                        info!("Successfully removed dm-verity device: {}", dm_name);
                    }

                    // Detach loop device
                    let status = Command::new("losetup").arg("-d").arg(layer_path).status()?;
                    if !status.success() {
                        error!("Failed to detach loop device for layer {:?}", layer_path);
                    } else {
                        info!("Successfully detached loop device for layer {:?}", layer_path);
                    }
                }
            }*/

            // Return a mount structure for `runc`
            let overlay_mount = api::types::Mount {
                r#type: "bind".into(),
                source: overlay_target.to_string_lossy().into(),
                target: "/".into(),
                options: vec!["bind".into(), "rw".into()],
            };

            info!(
                "mounts_from_snapshot(): returning mount struct for runc: type={}, source={}, target={}, options={:?}",
                overlay_mount.r#type, overlay_mount.source, overlay_mount.target, overlay_mount.options
            );

            return Ok(vec![overlay_mount]);
        }

        opts.push(format!("{PREFIX}.overlay-rw"));
        opts.push(format!("lowerdir={}", layers.join(":")));

        return Ok(vec![api::types::Mount {
            r#type: "fuse3.kata-overlay".into(),
            source: "/".into(),
            target: String::new(),
            options: opts,
        }]);
    }
}

/// The snapshotter that creates tar devices.
pub(crate) struct TarDevSnapshotter {
    store: RwLock<Store>,
    containerd_path: String,
    containerd_client: RwLock<Option<Client>>,
}

impl TarDevSnapshotter {
    /// Creates a new instance of the snapshotter.
    ///
    /// `root` is the root directory where the snapshotter state is to be stored.
    pub(crate) fn new(root: &Path, containerd_path: String) -> Self {
        Self {
            containerd_path,
            store: RwLock::new(Store::new(root)),
            containerd_client: RwLock::new(None),
        }
    }

    async fn prepare_unpack_dir(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Status> {
        let extract_dir;
        {
            let mut store = self.store.write().await;
            extract_dir = store.extract_dir_to_write(&key)?;
            store.write_snapshot(Kind::Active, key, parent, labels)?;
        }
        Ok(vec![api::types::Mount {
            r#type: "bind".into(),
            source: extract_dir.to_string_lossy().into(),
            target: String::new(),
            options: vec!["bind".into()],
        }])
    }

    async fn get_layer_image(&self, fname: &PathBuf, digest: &str) -> Result<(), Status> {
        let mut file = tokio::fs::File::create(fname).await?;
        let req = ReadContentRequest {
            digest: digest.to_string(),
            offset: 0,
            size: 0,
        };
        let req = with_namespace!(req, "k8s.io");

        loop {
            let guard = self.containerd_client.read().await;
            let Some(client) = &*guard else {
                drop(guard);
                info!("Connecting to containerd at {}", self.containerd_path);
                let c = Client::from_path(&self.containerd_path)
                    .await
                    .map_err(|_| Status::unknown("unable to connect to containerd"))?;
                *self.containerd_client.write().await = Some(c);
                continue;
            };
            let mut c = client.content();
            let resp = c.read(req).await?;
            let mut stream = resp.into_inner();
            while let Some(chunk) = stream.message().await? {
                if chunk.offset < 0 {
                    debug!("Containerd reported a negative offset: {}", chunk.offset);
                    return Err(Status::invalid_argument("negative offset"));
                }
                file.seek(io::SeekFrom::Start(chunk.offset as u64)).await?;
                file.write_all(&chunk.data).await?;
            }

            return Ok(());
        }
    }

    /// Creates a new snapshot for an image layer.
    ///
    /// It downloads, decompresses, and creates the index for the layer before writing the new
    /// snapshot.
    async fn prepare_image_layer(
        &self,
        key: String,
        parent: String,
        mut labels: HashMap<String, String>,
        salt: Vec<u8>,
    ) -> Result<(), Status> {
        let dir = self.store.read().await.staging_dir()?;

        {
            let Some(digest_str) = labels.get(TARGET_LAYER_DIGEST_LABEL) else {
                error!("abort");
                return Err(Status::invalid_argument(
                    "missing target layer digest label",
                ));
            };

            let name = dir.path().join(name_to_hash(&key));
            let mut gzname = name.clone();
            gzname.set_extension("gz");
            trace!("Fetching layer image to {:?}", &gzname);
            self.get_layer_image(&gzname, digest_str).await?;

            // TODO: Decompress in stream instead of reopening.
            // Decompress data.
            trace!("Decompressing {:?} to {:?}", &gzname, &name);
            let root_hash = tokio::task::spawn_blocking(move || -> io::Result<_> {
                let compressed = fs::File::open(&gzname)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&name)?;
                let mut gz_decoder = flate2::read::GzDecoder::new(compressed);
                std::io::copy(&mut gz_decoder, &mut file)?;

                trace!("Appending index to {:?}", &name);
                file.rewind()?;
                tarindex::append_index(&mut file)?;

                trace!("Appending dm-verity tree to {:?}", &name);
                let root_hash = verity::append_tree::<Sha256>(&mut file, &salt)?;

                trace!("Root hash for {:?} is {:x}", &name, root_hash);
                Ok(root_hash)
            })
            .await
            .map_err(|_| Status::unknown("error in worker task"))??;

            // Store a label with the root hash so that we can recall it later when mounting.
            labels.insert(ROOT_HASH_LABEL.into(), format!("{:x}", root_hash));
        }

        // Move file to its final location and write the snapshot.
        {
            let from = dir.path().join(name_to_hash(&key));
            let mut store = self.store.write().await;
            let to = store.layer_path_to_write(&key)?;
            trace!("Renaming from {:?} to {:?}", &from, &to);
            tokio::fs::rename(from, to).await?;
            store.write_snapshot(Kind::Committed, key, parent, labels)?;
        }

        trace!("Layer prepared");
        Ok(())
    }

    async fn commit_impl(
        &self,
        name: String,
        key: String,
        labels: HashMap<String, String>,
    ) -> Result<(), Status> {
        let (salt, parent) = {
            // Needs to be in the closure to release the lock
            let mut store = self.store.write().await;
            let info = store.read_snapshot(&key)?;
            if info.kind != Kind::Active {
                return Err(Status::failed_precondition("snapshot is not active"));
            }

            let digest = match info.labels.get(TARGET_LAYER_DIGEST_LABEL) {
                None => {
                    return Err(Status::unimplemented(
                        "no support for commiting arbitrary snapshots",
                    ));
                }
                Some(digest) => digest,
            };

            let result = store.lazy_read_signatures();
            match result {
                Err(e) => {
                    return Err(Status::failed_precondition(format!(
                        "signature read failure: {e}"
                    )))
                }
                Ok(()) => (),
            };

            trace!("Looking up salt for {digest}");
            let salt = store.get_salt(digest);

            (salt, info.parent)
        };

        match salt {
            Err(e) => Err(Status::failed_precondition(format!(
                "signature missing: {e}"
            ))),
            Ok(salt) => self.prepare_image_layer(name, parent, labels, salt).await,
        }
    }

    async fn usage_impl(&self, key: String) -> Result<Usage, Status> {
        let store = self.store.read().await;

        let info = store.read_snapshot(&key)?;
        if info.kind != Kind::Committed {
            // Only committed snapshots consume storage.
            return Ok(Usage { inodes: 0, size: 0 });
        }

        let mut file = tokio::fs::File::open(store.layer_path(&key)).await?;
        let len = file.seek(io::SeekFrom::End(0)).await?;
        Ok(Usage {
            // TODO: Read the index "header" to determine the inode count.
            inodes: 1,
            size: len as _,
        })
    }

    async fn mounts_impl(&self, key: String) -> Result<Vec<api::types::Mount>, Status> {
        let store = self.store.read().await;
        let info = store.read_snapshot(&key)?;

        if info.kind != Kind::View && info.kind != Kind::Active {
            return Err(Status::failed_precondition(
                "snapshot is not active nor a view",
            ));
        }

        if info.labels.get(TARGET_LAYER_DIGEST_LABEL).is_some() {
            let extract_dir = store.extract_dir(&key);
            info!("mounts(): snapshot: {}, pass extract_dir to containerd so that it unpacks the layer to extract_dir: {}", &info.name, extract_dir.to_string_lossy());
            Ok(vec![api::types::Mount {
                r#type: "bind".into(),
                source: extract_dir.to_string_lossy().into(),
                target: String::new(),
                options: Vec::new(),
            }])
        } else {
            info!(
                "mounts(): snapshot: {}, ready to use, preparing itself and parents ",
                &info.name
            );
            store.mounts_from_snapshot(&info.parent, true)
        }
    }

    async fn remove_impl(&self, key: String) -> Result<(), Status> {
        let store = self.store.write().await;

        // TODO: Move this to store.
        if let Ok(info) = store.read_snapshot(&key) {
            match info.kind {
                Kind::Committed => {
                    if info.labels.get(TARGET_LAYER_DIGEST_LABEL).is_some() {
                        // Try to delete a layer. It's ok if it's not found.
                        if let Err(e) = fs::remove_file(store.layer_path(&key)) {
                            if e.kind() != io::ErrorKind::NotFound {
                                return Err(e.into());
                            }
                        }
                    }
                }
                Kind::Active => {
                    if let Err(e) = tokio::fs::remove_dir_all(store.extract_dir(&key)).await {
                        if e.kind() != io::ErrorKind::NotFound {
                            return Err(e.into());
                        }
                    }
                }
                _ => {}
            }
        }

        let name = store.snapshot_path(&key, false)?;
        fs::remove_file(name)?;

        Ok(())
    }
}

#[tonic::async_trait]
impl Snapshotter for TarDevSnapshotter {
    type Error = Status;

    async fn stat(&self, key: String) -> Result<Info, Self::Error> {
        trace!("stat({})", key);

        let result = self.store.read().await.read_snapshot(&key);

        if result.is_err() {
            error!("stat() failed with: {:#?}", result);
        }
        return result;
    }

    async fn update(
        &self,
        info: Info,
        fieldpaths: Option<Vec<String>>,
    ) -> Result<Info, Self::Error> {
        trace!("update({:?}, {:?})", info, fieldpaths);
        Err(Status::unimplemented("no support for updating snapshots"))
    }

    async fn usage(&self, key: String) -> Result<Usage, Self::Error> {
        trace!("usage({})", key);

        let result = self.usage_impl(key).await;
        if result.is_err() {
            error!("usage() failed with: {:#?}", result);
        }
        return result;
    }

    async fn mounts(&self, key: String) -> Result<Vec<api::types::Mount>, Self::Error> {
        trace!("mounts({})", key);
        let result = self.mounts_impl(key).await;
        if result.is_err() {
            error!("mounts() failed with: {:#?}", result);
        }
        return result;
    }

    async fn prepare(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Status> {
        trace!("prepare({}, {}, {:?})", key, parent, labels);

        let result = {
            // There are two reasons for preparing a snapshot: to build an image and to actually use it
            // as a container image. We determine the reason by the presence of the snapshot-ref label.
            if labels.get(TARGET_LAYER_DIGEST_LABEL).is_some() {
                info!("prepare(): prepare a staging dir for containerd tar data extraction");
                self.prepare_unpack_dir(key, parent, labels).await
            } else {
                info!("prepare(): create active snapshot");
                self.store
                    .write()
                    .await
                    .prepare_snapshot_for_use(Kind::Active, key, parent, labels)
            }
        };

        if result.is_err() {
            error!("prepare() failed with: {:#?}", result);
        }
        return result;
    }

    async fn view(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Self::Error> {
        trace!("view({}, {}, {:?})", key, parent, labels);

        let result =
            self.store
                .write()
                .await
                .prepare_snapshot_for_use(Kind::View, key, parent, labels);

        if result.is_err() {
            error!("view() failed with {:#?}", result);
        }
        return result;
    }

    async fn commit(
        &self,
        name: String,
        key: String,
        labels: HashMap<String, String>,
    ) -> Result<(), Self::Error> {
        trace!("commit({}, {}, {:?})", name, key, labels);
        let result = self.commit_impl(name, key, labels).await;
        if result.is_err() {
            error!("commit() failed with: {:#?}", result);
        }
        return result;
    }

    async fn remove(&self, key: String) -> Result<(), Self::Error> {
        trace!("remove({})", key);

        let result = self.remove_impl(key).await;
        if result.is_err() {
            error!("remove() failed with {:#?}", result);
        }
        return result;
    }

    type InfoStream = impl tokio_stream::Stream<Item = Result<Info, Self::Error>> + Send + 'static;
    async fn list(&self, _: String, _: Vec<String>) -> Result<Self::InfoStream, Self::Error> {
        trace!("walk()");
        let store = self.store.read().await;
        let snapshots_dir = store.root.join("snapshots");
        Ok(async_stream::try_stream! {
            let mut files = tokio::fs::read_dir(snapshots_dir).await?;
            while let Some(p) = files.next_entry().await? {
                if let Ok(f) = fs::File::open(p.path()) {
                    if let Ok(i) = serde_json::from_reader(f) {
                        yield i;
                    }
                }
            }
        })
    }
}

/// Converts the given name to a string representation of its sha256 hash.
fn name_to_hash(name: &str) -> String {
    let path = Path::new(name);
    let mut hasher = Sha256::new();
    match path.file_name() {
        Some(n) => hasher.update(n.as_bytes()),
        None => hasher.update(name),
    }
    format!("{:x}", hasher.finalize())
}
