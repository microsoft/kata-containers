use anyhow::{anyhow, Context, Result};
use async_recursion::async_recursion;
use base64::prelude::{Engine, BASE64_STANDARD};
use containerd_client::{services::v1::ReadContentRequest, tonic::Request, with_namespace, Client};
use containerd_snapshots::{api, Info, Kind, Snapshotter, Usage};
use log::{debug, error, info, trace, warn};
use nix::mount::MsFlags;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{
    digest::{typenum::Unsigned, OutputSizeUser},
    Digest, Sha256,
};
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
use erofs_common::utils;
use oci_client::client::Client as OCI_Client;
use oci_client::client::ClientConfig;
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;

const ROOT_HASH_LABEL: &str = "io.katacontainers.dm-verity.root-hash";
const ROOT_HASH_SIG_LABEL: &str = "io.katacontainers.dm-verity.root-hash-sig";
const TARGET_LAYER_DIGEST_LABEL: &str = "containerd.io/snapshot/cri.layer-digest";
const TARGET_MANIFEST_DIGEST_LABEL: &str = "containerd.io/snapshot/cri.manifest-digest";
const TARGET_IMAGE_REF_LABEL: &str = "containerd.io/snapshot/cri.image-ref";

const TAR_GZ_EXTENSION: &str = "tar.gz";
const TAR_EXTENSION: &str = "tar";

/// Path from where to scan for .json standalone signature manifests
const SIGNATURE_STORE: &str = "/var/lib/containerd/io.containerd.snapshotter.v1.tardev/signatures";

// borrowed from oci-distribution crate, which alas does not build with rustc
// 1.75, which is used by AzL3

/// The mediatype for an docker v2 schema 2 manifest.
pub const IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// The mediatype for an docker v2 shema 2 manifest list.
pub const IMAGE_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
/// The mediatype for an OCI image index manifest.
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
/// The mediatype for an OCI image manifest.
pub const OCI_IMAGE_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The mediatype for a layer.
pub const IMAGE_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
/// The mediatype for a layer that is gzipped.
pub const IMAGE_LAYER_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
/// The mediatype that Docker uses for a layer that is tarred.
pub const IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE: &str = "application/vnd.docker.image.rootfs.diff.tar";
/// The mediatype that Docker uses for a layer that is gzipped.
pub const IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE: &str =
    "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// The image layer digest from the signature manifest.
pub const IMAGE_LAYER_DIGEST_LABEL: &str = "image.layer.digest";
/// The image layer root hash from the signature manifest.
pub const IMAGE_LAYER_ROOT_HASH_LABEL: &str = "image.layer.root_hash";
/// The image layer signature from the signature manifest.
pub const IMAGE_LAYER_SIGNATURE_LABEL: &str = "image.layer.signature";
/// The image layer signature artifact type.
pub const SIGNATURE_ARTIFACT_TYPE: &str = "application/vnd.oci.mt.pkcs7";

#[derive(Serialize, Deserialize)]
struct ImageInfo {
    name: String,
    layers: Vec<LayerInfo>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
struct LayerInfo {
    digest: String,    // `sha256:` + hex encoded
    root_hash: String, // hex encoded
    signature: String, // base64 encoded
}

struct Store {
    root: PathBuf,
    signatures: Option<HashMap<String, LayerInfo>>, // digest to layer info
}

impl Store {
    fn new(root: &Path) -> Self {
        let mut store = Self {
            root: root.into(),
            signatures: Some(<HashMap<String, LayerInfo>>::new()),
        };
        // Load signatures from standalone signatures.json file at initialization
        if let Err(e) = store.read_signatures_from_file() {
            panic!("Failed to read signatures from file during Store::new: {}", e);
        }
        store
    }

    async fn lazy_read_signatures(&mut self, image_name: &String, image_digest: &String) -> Result<()> {
        let signatures_count = self.signatures.as_ref().map(|s| s.len()).unwrap_or(0);
        if let Err(e) = self.read_signatures_from_registry(image_name, image_digest).await {
            debug!("Failed to read signatures from registry for image {}: {}", image_name, e);
        }
        debug!("Loaded {} signatures from registry", self.signatures.as_ref().map(|s| s.len()).unwrap_or(0) - signatures_count);
        Ok(())
    }

    async fn read_signatures_from_registry(&mut self, image_name: &String, image_digest: &String) -> Result<(), Box<dyn std::error::Error>> {
        // Create a client configuration
        let config: ClientConfig = ClientConfig::default();
        // Initialize the OCI client
        let client: OCI_Client = OCI_Client::new(config);
        // Authenticate with the registry (if needed)
        let auth: RegistryAuth = RegistryAuth::Anonymous;
        let image_ref: Reference = image_name.parse().map_err(|e| {
            anyhow!("Failed to parse image reference '{}': {}", image_name, e)
        })?;
        // Store authentication if needed
        client.store_auth_if_needed(image_ref.registry(), &auth).await;
        debug!("Loading signatures of image reference from registry: {}", image_ref);

        // Construct the image reference with digest
        let image_manifest_ref = Reference::with_digest(
            image_ref.registry().to_string(),
            image_ref.repository().to_string(),
            image_digest.to_string(),
        );

        self.load_referrers(&client, &image_manifest_ref, &auth).await.map_err(|e| {
            anyhow!("Error processing referrers: {}", e)
        })?;

        Ok(())
    }

    async fn load_referrers(
        &mut self,
        client: &OCI_Client,
        image_ref: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(), Box<dyn std::error::Error>> {
        
        // Fetch the referrers list with the specified artifact type
        match client.pull_referrers(image_ref, Some(SIGNATURE_ARTIFACT_TYPE)).await {
            Ok(referrers) => {
                if referrers.manifests.is_empty() {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "No signature manifests found in referrers.",
                    )));
                }
                // Process the first manifest in the referrers list, should pick the latest one in the future
                let sig_manifest = referrers.manifests[0].clone();
                debug!("signature manifest Digest: {}", sig_manifest.digest);
                // Construct the reference for the sig manifest
                let sig_manifest_ref: Reference = Reference::with_digest(
                    image_ref.registry().to_string(),
                    image_ref.repository().to_string(),
                    sig_manifest.digest.to_string(),
                );
    
                // Pull the sig manifest using the constructed reference and auth
                match client.pull_image_manifest(&sig_manifest_ref, &auth).await {
                    Ok((sig_manifest, _)) => {
                        for layer in sig_manifest.layers {
                            if let Some((digest, root_hash, signature)) = layer
                            .annotations
                            .as_ref()
                            .and_then(|annotations| {
                                Some((
                                    annotations.get(IMAGE_LAYER_DIGEST_LABEL)?,
                                    annotations.get(IMAGE_LAYER_ROOT_HASH_LABEL)?,
                                    annotations.get(IMAGE_LAYER_SIGNATURE_LABEL)?,
                                ))
                            }) {
                                // Construct the LayerInfo
                                let layer_info = LayerInfo {
                                    digest: digest.clone(),
                                    root_hash: root_hash.clone(),
                                    signature: signature.clone(),
                                };
                                // Store the LayerInfo in the signatures map
                                if let Some(signatures) = self.signatures.as_mut() {
                                    signatures.insert(digest.clone(), layer_info.clone());
                                }

                                debug!("Layer Info:");
                                debug!("  Digest: {}", layer_info.digest);
                                debug!("  Root Hash: {}", layer_info.root_hash);
                                debug!("  Signature: {}", layer_info.signature);
                            } else {
                                debug!("Layer digest: {} has no annotations.", layer.digest);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to pull signature manifest: {}", e);
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch referrers: {}", e);
            }
        }
        Ok(())
    }

    fn has_signature(&self, digest: &str) -> bool {
        match &self.signatures {
            Some(signatures) => signatures.contains_key(digest),
            None => false,
        }
    }

    fn read_signatures_from_file(&mut self) -> Result<()> {
        let paths = std::fs::read_dir(Path::new(SIGNATURE_STORE))?;
        let mut signatures = HashMap::new();
        for signatures_json_path in paths {
            let signatures_json = std::fs::read_to_string(
                signatures_json_path
                    .context("failed to load signature file path")?
                    .path(),
            )?;
            let image_info_list = serde_json::from_str::<Vec<ImageInfo>>(signatures_json.as_str())?;
            for image_info in image_info_list {
                for layer_info in image_info.layers {
                    signatures.insert(layer_info.digest.clone(), layer_info.clone());
                }
            }
        }

        if !signatures.is_empty() {
            debug!("Loaded {} signatures from signatures.json", signatures.len());
            self.signatures = Some(signatures);
        }

        Ok(())
    }

    fn get_info_from_digest(&self, digest: &str) -> Option<LayerInfo> {
        match self.signatures {
            Some(ref signatures) => signatures.get(digest).map(|layer_info| LayerInfo {
                digest: layer_info.digest.clone(),
                root_hash: layer_info.root_hash.clone(),
                signature: layer_info.signature.clone(),
            }),
            None => None,
        }
    }

    fn load_signature(&self, hash: &str, signature: &str) -> Result<String> {
        debug!("Loading signature {signature} for root hash {hash}");

        let signature_name = format!("verity:{hash}");

        // https://lkml.org/lkml/2019/7/17/762
        // https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html
        let keyctl = Command::new("keyctl")
            .stdin(Stdio::piped())
            .arg("padd")
            .arg("user")
            .arg(&signature_name)
            .arg("@s")
            .spawn()
            .context("failed to start keyctl")?;
        keyctl
            .stdin
            .as_ref()
            .context("failed to bind to the input of keyctl")?
            .write_all(
                &BASE64_STANDARD
                    .decode(signature)
                    .context("failed to decode signature")?,
            )
            .context("failed to write keyctl input")?;
        let output = keyctl
            .wait_with_output()
            .context("failed to wait for keyctl output")?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("failed to load signature, keyctl failed"));
        }

        Ok(signature_name)
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
    fn snapshot_path(&self, name: &str, write: bool) -> Result<PathBuf> {
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
    fn layer_path_to_write(&self, name: &str) -> Result<PathBuf> {
        let path = self.layer_path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(path)
    }

    /// Reads the information from storage for the given snapshot name.
    fn read_snapshot(&self, name: &str) -> Result<Info> {
        let path = self.snapshot_path(name, false)?;
        let file = fs::File::open(&path)
            .context(format!("unable to open snapshot ('{}')", path.display()))?;
        serde_json::from_reader(file)
            .context(format!("unable to read snapshot ('{}')", path.display()))
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
    ) -> Result<()> {
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
        serde_json::to_writer_pretty(file, &info).context("unable to write snapshot")
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
    ) -> Result<Vec<api::types::Mount>> {
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
        signature_name: Option<String>,
    ) -> Result<(u64, u64, String, String)> {
        debug!("prepare_dm_target for loop device ({path}/{hash}/{signature_name:?})");
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
            .context("Invalid data size")?;
        if data_size > size {
            return Err(anyhow!(
                "Data size ({data_size}) is greater than device size ({size}) for device {path}"
            ));
        }

        // generate dm-verity table, use all zero salt
        // TODO: Store other parameters in super block: version, hash type,
        // salt.
        let salt = '0'
            .to_string()
            .repeat(<Sha256 as OutputSizeUser>::OutputSize::USIZE * 2);
        let signature_parameters = if let Some(signature_name) = signature_name {
            format!(" 2 root_hash_sig_key_desc {signature_name}")
        } else {
            String::new()
        };
        let construction_parameters = format!(
                "1 {path} {path} {data_block_size} {hash_block_size} {} {} sha256 {hash} {salt}{signature_parameters}",
                data_size / data_block_size,
                (data_size + hash_block_size - 1) / hash_block_size,
            );
        debug!("dm-verity construction params: {construction_parameters}");
        Ok((0, data_size / 512, "verity".into(), construction_parameters))
    }

    // Creates dm-verity device for a given layer file
    fn create_dm_verity_device(
        &self,
        layer_path: &str,
        root_hash: &str,
        root_hash_sig_name: Option<String>,
    ) -> Result<String> {
        let dm = devicemapper::DM::new()?;
        let layer_name = Path::new(layer_path)
            .file_name()
            .context("Unable to get file name from layer path")?
            .to_str()
            .context("Unable to convert file name to UTF-8 string")?;

        debug!("create_dm_verity_device for layer: {}", layer_name);

        let name = devicemapper::DmName::new(&layer_name)?;
        let opts = devicemapper::DmOptions::default().set_flags(devicemapper::DmFlags::DM_READONLY);

        if let Err(e) = dm.device_create(name, None, opts) {
            error!("Failed to create Device Mapper device: {:?}", e);
            return Err(e.into());
        }
        let id = devicemapper::DevId::Name(name);

        let result = (|| {
            // Step 1: Set up loop device for the given layer_path
            let setup_output = Command::new("losetup")
                .arg("-fP")
                .arg(layer_path)
                .output()
                .context("Failed to execute losetup command to create loop device")?;

            if !setup_output.status.success() {
                error!(
                    "Failed to set up loop device: {:?}",
                    String::from_utf8_lossy(&setup_output.stderr)
                );
                return Err(anyhow!(
                    "Failed to set up loop device: {:?}",
                    String::from_utf8_lossy(&setup_output.stderr)
                ));
            }
            trace!("set up loop device");

            // Step 2: Find the loop device associated with the file
            let loop_output = Command::new("losetup")
                .arg("-a")
                .output()
                .context("Failed to list loop devices")?;

            let loop_output_str = String::from_utf8_lossy(&loop_output.stdout);
            let loop_device = loop_output_str
                .lines()
                .find(|line| line.contains(layer_path))
                .and_then(|line| line.split(":").next())
                .context(format!("Could not find loop device for {}", layer_path))?;

            trace!("selected newly created loop device: {}", loop_device);

            // Use the loop device path for DM-Verity
            let device_path = loop_device;

            // Step 3: Prepare DM-Verity target
            let target = self.prepare_dm_target(device_path, root_hash, root_hash_sig_name)?;

            // Step 4: Load the DM table for DM-Verity
            dm.table_load(&id, &[target], opts)
                .context("Unable to load DM-Verity table")?;
            trace!("loaded DM table for DM-Verity");

            // Step 5: Suspend the DM device to make it active
            dm.device_suspend(&id, opts)
                .context("Unable to suspend DM device")?;
            trace!("suspended DM device for activation");

            // Step 6: Return success, with the path of the DM-Verity device
            Ok(format!("/dev/mapper/{}", layer_name))
        })();

        // If there is an error, remove the DM device and clean up the loop device
        result.map_err(|e| {
            // Remove the DM device if it was created
            if let Err(remove_err) = dm.device_remove(&id, devicemapper::DmOptions::default()) {
                warn!(
                    "Unable to remove DM device ({}): {:?}",
                    layer_name, remove_err
                );
            }

            // Clean up the loop device
            trace!("Cleaning up loop device: {}", layer_path);
            let detach_output = Command::new("losetup")
                .arg("-d")
                .arg(layer_path)
                .output()
                .expect("Failed to execute losetup detach command");

            if !detach_output.status.success() {
                warn!(
                    "Failed to detach loop device: {:?}",
                    String::from_utf8_lossy(&detach_output.stderr)
                );
            } else {
                debug!("Successfully detached loop device: {}", layer_path);
            }

            error!("Error occurred during DM-Verity setup: {:?}", e);
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
                .context(format!("Failed to create mount point: {}", target))?;
        }

        // Attempt the mount operation
        nix::mount::mount(
            Some(source_path),
            target_path,
            Some(fstype),
            flags,
            Some(options),
        )
        .context(format!("Failed to mount {} to {}", source, target))?;

        Ok(())
    }

    fn mounts_from_snapshot(&self, parent: &str, do_mount: bool) -> Result<Vec<api::types::Mount>> {
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
                return Err(anyhow!("parent snapshot is not committed",));
            }

            let root_hash = match info.labels.get(ROOT_HASH_LABEL) {
                Some(rh) => rh,
                None => {
                    return Err(anyhow!("parent snapshot has no root hash stored",));
                }
            };

            let name = name_to_hash(&p);
            let layer_info = format!(
                "{name},erofs,ro,{PREFIX}.block_device=file,{PREFIX}.is-layer,{PREFIX}.root-hash={root_hash}");
            trace!(
                "mounts_from_snapshot(): processing snapshots: {}, layername: {}",
                &info.name,
                &name
            );

            if do_mount {
                trace!("mounts_from_snapshot(): performing erofs mounting via dm-verity");
                // Extract layer information
                let mut fields = layer_info.split(',');
                let src = if let Some(p) = fields.next() {
                    if !p.is_empty() && p.as_bytes()[0] != b'/' {
                        src_prefix.join(Path::new(p))
                    } else {
                        Path::new(p).to_path_buf()
                    }
                } else {
                    return Err(anyhow!("Missing source path in layer info",));
                };
                trace!("src: {}", src.display());

                let fs_type = fields.next().ok_or_else(|| {
                    Status::invalid_argument("Missing filesystem type in layer info")
                })?;
                trace!("fs_type: {}", fs_type);

                let fs_opts = fields
                    .filter(|o| !o.starts_with("io.katacontainers."))
                    .fold(String::new(), |a, b| {
                        if a.is_empty() {
                            b.into()
                        } else {
                            format!("{a},{b}")
                        }
                    });
                trace!("fs_opts: {}", fs_opts);

                let mount_path = self.root.join("mounts").join(&name);
                trace!("mount_path: {}", mount_path.display());
                std::fs::create_dir_all(&mount_path)?;

                // Step 0: Check if the dm-verity device already exists
                let dm_verity_device = format!("/dev/mapper/{}", name);
                if Path::new(&dm_verity_device).exists() {
                    trace!(
                        "dm-verity device already exists for layer {}: {}",
                        name,
                        dm_verity_device
                    );
                } else {
                    let signature_name = (match info.labels.get(ROOT_HASH_SIG_LABEL) {
                        Some(root_hash_sig) => {
                            match self.load_signature(root_hash, root_hash_sig) {
                                Ok(name) => Ok(Some(name)),
                                Err(e) => Err(e),
                            }
                        }
                        None => Ok(None),
                    })
                    .context("Failed to load signature")?;
                    if signature_name.is_none() {
                        warn!("No signature found for layer {}", name);
                    }

                    // Step 1:  Create a dm-verity device for the tarfs layer
                    let created_dm_verity_device = self
                        .create_dm_verity_device(src.to_str().unwrap(), root_hash, signature_name)
                        .context(format!(
                            "Failed to create dm-verity device for source {:?}",
                            src
                        ))?;
                    debug!(
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
                    debug!(
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
                    .context(format!(
                        "Failed to mount dm-verity device {} to {:?}",
                        dm_verity_device, mount_path
                    ))?;
                    debug!(
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
            trace!("mounts_from_snapshot(): perform overlay mounting");
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
            trace!(
                "Combining dm-verity layers into overlay lowerdirs: {}",
                lowerdirs
            );

            // DEBUG: Validate that lowerdirs does not exceed PATH_MAX
            if lowerdirs.len() > 4096 {
                return Err(anyhow!(
                    "Lowerdirs string exceeds allowable length: {}",
                    lowerdirs.len()
                ));
            }

            // Perform an overlay mount
            let opts = format!(
                "lowerdir={},upperdir={},workdir={}",
                lowerdirs,
                overlay_upper.to_string_lossy(),
                overlay_work.to_string_lossy()
            );
            nix::mount::mount(
                Some("overlay"),
                &overlay_target,
                Some("overlay"),
                MsFlags::empty(),
                Some(opts.as_str()),
            )
            .context(format!(
                "Failed to mount overlay to {}",
                overlay_target.display(),
            ))?;

            trace!("Overlay mount completed at {:?}", overlay_target);

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

            debug!(
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
            extract_dir = store
                .extract_dir_to_write(&key)
                .map_err(|e| Status::unknown(format!("failed to create extract dir: {e}")))?;
            store
                .write_snapshot(Kind::Active, key.clone(), parent, labels)
                .map_err(|e| Status::unknown(format!("failed to write snapshot: {e}")))?;
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
                trace!("Connecting to containerd at {}", self.containerd_path);
                let c = Client::from_path(&self.containerd_path)
                    .await
                    .map_err(|e| {
                        Status::unknown(format!("unable to connect to containerd: {e}"))
                    })?;
                *self.containerd_client.write().await = Some(c);
                continue;
            };
            let mut c = client.content();
            let resp = c.read(req).await?;
            let mut stream = resp.into_inner();
            while let Some(chunk) = stream.message().await? {
                if chunk.offset < 0 {
                    error!("Containerd reported a negative offset: {}", chunk.offset);
                    return Err(Status::invalid_argument("negative offset"));
                }
                file.seek(io::SeekFrom::Start(chunk.offset as u64)).await?;
                file.write_all(&chunk.data).await?;
            }

            return Ok(());
        }
    }

    /// Fetches the OCI manifest for the given digest.
    async fn get_oci_manifest(&self, digest_str: &str) -> Result<Value, Status> {
        let req = ReadContentRequest {
            digest: digest_str.to_string(),
            offset: 0,
            size: 0,
        };
        let req = with_namespace!(req, "k8s.io");

        loop {
            let guard = self.containerd_client.read().await;
            let Some(client) = &*guard else {
                drop(guard);
                trace!("Connecting to containerd at {}", self.containerd_path);
                let c = Client::from_path(&self.containerd_path)
                    .await
                    .map_err(|e| {
                        Status::unknown(format!("unable to connect to containerd: {e}"))
                    })?;
                *self.containerd_client.write().await = Some(c);
                continue;
            };
            let mut c = client.content();
            let resp = c.read(req).await?;
            let mut stream = resp.into_inner();
            let mut buf = Vec::new();
            while let Some(chunk) = stream.message().await? {
                if chunk.offset < 0 {
                    error!("Containerd reported a negative offset: {}", chunk.offset);
                    return Err(Status::invalid_argument("negative offset"));
                }

                // aggregate the chunks in memory
                buf.extend_from_slice(&chunk.data);
            }
            return serde_json::from_slice(&buf).map_err(|e| {
                error!(
                    "failed to parse manifest with digest {digest_str}: {e}, manifest: {:?}",
                    buf
                );
                Status::invalid_argument(format!("failed to parse manifest: {e}"))
            });
        }
    }

    /// Fetches the OCI image manifest for the given digest.
    #[async_recursion]
    async fn get_image_manifest(&self, digest_str: &str) -> Result<Map<String, Value>, Status> {
        let manifest = self
            .get_oci_manifest(digest_str)
            .await
            .map_err(|e| Status::invalid_argument(format!("failed to get OCI manifest: {e}")))?
            .as_object()
            .ok_or(Status::aborted("failed to deserialize OCI manifest"))?
            .clone();
        let media_type = manifest
            .get_key_value("mediaType")
            .and_then(|kv| kv.1.as_str())
            .or({
                if manifest.get_key_value("layers").is_some() {
                    warn!("failed to deserialize OCI manifest, 'mediaType' attribute is missing, but found 'layers' attribute, assuming image manifest");
                    Some(IMAGE_MANIFEST_MEDIA_TYPE)
                } else {
                    warn!("failed to deserialize OCI manifest, 'mediaType' attribute is missing, assuming image index manifest");
                    Some(IMAGE_MANIFEST_LIST_MEDIA_TYPE)
                }
            })
            .unwrap();
        match media_type {
            OCI_IMAGE_MEDIA_TYPE | IMAGE_MANIFEST_MEDIA_TYPE => Ok(manifest),
            OCI_IMAGE_INDEX_MEDIA_TYPE | IMAGE_MANIFEST_LIST_MEDIA_TYPE => {
                let digest_str = self.get_platform_manifest_digest(&manifest)?;
                Box::pin(self.get_image_manifest(&digest_str)).await
            }
            _ => Err(Status::invalid_argument(format!(
                "unsupported OCI manifest media type: {}",
                media_type
            ))),
        }
    }

    /// Finds the linux/amd64 variant in the OCI image index and returns its digest.
    fn get_platform_manifest_digest(
        &self,
        manifest: &Map<String, Value>,
    ) -> Result<String, Status> {
        let manifests = manifest
            .get_key_value("manifests")
            .and_then(|kv| kv.1.as_array())
            .ok_or(Status::invalid_argument(
                "Failed to deserialize OCI image index, manifests is missing",
            ))?;

        // Find the linux/amd64 variant
        let manifest = manifests
            .iter()
            .find(|manifest| {
                let result = manifest
                    .as_object()
                    .and_then(|m| m.get_key_value("platform"))
                    .and_then(|kv| kv.1.as_object())
                    .and_then(|platform| {
                        Some(
                            platform
                                .get_key_value("os")
                                .map(|kv| kv.1.as_str() == Some("linux"))
                                .unwrap_or(false)
                                && platform
                                    .get_key_value("architecture")
                                    .map(|kv| kv.1.as_str() == Some("amd64"))
                                    .unwrap_or(false),
                        )
                    });
                result.unwrap_or(false)
            })
            .ok_or(Status::invalid_argument(
                "No linux/amd64 variant found in OCI image index",
            ))
            .map(|manifest| manifest.to_owned())?;

        manifest
            .as_object()
            .and_then(|manifest| {
                manifest
                    .get_key_value("digest")
                    .and_then(|kv| kv.1.as_str())
                    .and_then(|s| Some(s.to_owned()))
            })
            .ok_or(Status::invalid_argument(
                "Failed to deserialize OCI image index, digest is missing",
            ))
    }

    /// Fetches and processes an image layer.
    ///
    /// Downloads the layer, decompresses it if needed, appends a tar index,
    /// and generates a dm-verity tree. Prepares the layer for use in the snapshotter.
    async fn fetch_and_process_layer(
        &self,
        upstream_name: PathBuf,
        base_name: PathBuf,
        digest_str: &str,
        layer_type: &str,
    ) -> Result<String, Status> {
        let layer_type = layer_type.to_string(); // Clone `layer_type` into an owned `String`

        debug!("Fetching {} layer image to {:?}", layer_type, upstream_name);

        // Fetch the layer image
        self.get_layer_image(&upstream_name, digest_str)
            .await
            .map_err(|download_err| {
                Status::unknown(format!("Failed to fetch layer image: {:?}", download_err))
            })?;

        // Process the layer
        let process_result = tokio::task::spawn_blocking({
            let upstream_name = upstream_name.clone();
            let base_name = base_name.clone();
            let layer_type = layer_type.clone(); // Move `layer_type` into the closure

            move || -> Result<_> {
                if layer_type == TAR_EXTENSION {
                    debug!("Renaming {:?} to {:?}", &upstream_name, &base_name);
                    std::fs::rename(&upstream_name, &base_name)?;
                }
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(layer_type == TAR_GZ_EXTENSION)
                    .open(&base_name)?;
                if layer_type == TAR_GZ_EXTENSION {
                    debug!("Decompressing {:?} to {:?}", &upstream_name, &base_name);
                    let compressed = fs::File::open(&upstream_name).map_err(|e| {
                        let file_error = format!(
                            "Failed to open file {:?} for decompression: {:?}",
                            &upstream_name, e
                        );
                        error!("{file_error}");
                        anyhow!(file_error)
                    })?;
                    let mut gz_decoder = flate2::read::MultiGzDecoder::new(compressed);

                    if let Err(e) = std::io::copy(&mut gz_decoder, &mut file) {
                        let copy_error = format!("failed to copy payload from gz decoder {:?}", e);
                        error!("{}", copy_error);
                        return Err(anyhow!(copy_error));
                    }
                }
                file.flush()?;
                drop(file);

                let layer_path = PathBuf::from(format!("{}_etm", base_name.to_string_lossy())); // etm = erofs meta + tar + merkle tree

                // Create an erofs metadata using mkfs.erofs
                utils::create_erofs_metadata(&base_name, &layer_path)?;

                // Append the decompressed tar file to the erofs metadata
                utils::append_tar_to_erofs_metadata(&base_name, &layer_path)?;

                // Cleanup the decompressed tar file
                std::fs::remove_file(&base_name)
                    .context("failed to remove decompressed tar file")?;

                // Append the dm-verity tree to the erofs metadata + tar
                trace!("Appending dm-verity tree to {:?}", &layer_path);
                let mut layer_file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&layer_path)?;
                let root_hash = verity::append_tree::<Sha256>(&mut layer_file)
                    .context("failed to append verity tree")?;

                // rename layer_path to base_name
                debug!("Renaming {:?} to {:?}", &layer_path, &base_name);
                std::fs::rename(&layer_path, &base_name)?;

                trace!("Root hash for {:?} is {:x}", &base_name, root_hash);
                Ok(root_hash)
            }
        })
        .await
        .map_err(|e| Status::unknown(format!("Error in fetch_and_process worker task: {:?}", e)))?;

        match process_result {
            Ok(generated_root_hash) => {
                let generated_root_hash = format!("{:x}", generated_root_hash);
                trace!("Generated root hash: {}", generated_root_hash);
                Ok(generated_root_hash)
            }
            Err(process_err) => Err(Status::unknown(format!(
                "Failed to process layer: {:?}",
                process_err
            ))),
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
        root_hash: Option<String>,     // hex encoded
        root_hash_sig: Option<String>, // base64 encoded
    ) -> Result<(), Status> {
        let dir = self.store.read().await.staging_dir()?;
        let base_name = dir.path().join(name_to_hash(&key));
        let snapshot_name = base_name.clone();

        {
            let Some(digest_str) = labels.get(TARGET_LAYER_DIGEST_LABEL) else {
                return Err(Status::invalid_argument(
                    "missing target layer digest label",
                ));
            };

            let Some(manifest_digest_str) = labels.get(TARGET_MANIFEST_DIGEST_LABEL) else {
                return Err(Status::invalid_argument(
                    "missing target manifest digest label",
                ));
            };

            let image_manifest =
                self.get_image_manifest(manifest_digest_str)
                    .await
                    .map_err(|e| {
                        Status::invalid_argument(format!("failed to get image manifest: {:?}", e))
                    })?;

            let layer = image_manifest
                .get_key_value("layers")
                .and_then(|kv| kv.1.as_array())
                .and_then(|layers| {
                    layers.iter().find(|layer| {
                        layer
                            .as_object()
                            .and_then(|layer| layer.get_key_value("digest").map(|kv| kv.1.as_str()))
                            .map(|s| s == Some(digest_str.as_str()))
                            .unwrap_or(false)
                    })
                })
                .ok_or(Status::aborted(format!(
                    "layer '{}' not found in image manifest: {:#?}",
                    digest_str, image_manifest
                )))?;

            let media_type = layer
                .as_object()
                .and_then(|layer| {
                    layer
                        .get_key_value("mediaType")
                        .and_then(|kv| kv.1.as_str())
                })
                .ok_or(Status::invalid_argument(format!(
                    "mediaType not found in layer {}",
                    digest_str
                )))?;

            debug!("layer digest {} media_type: {:?}", digest_str, media_type);

            let layer_type = match media_type {
                IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE | IMAGE_LAYER_GZIP_MEDIA_TYPE => {
                    TAR_GZ_EXTENSION
                }
                IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE | IMAGE_LAYER_MEDIA_TYPE => TAR_EXTENSION,
                _ => {
                    return Err(Status::invalid_argument(format!(
                        "unsupported layer media type: {}",
                        media_type
                    )));
                }
            };

            let upstream_name = base_name.with_extension(layer_type);

            // Retry logic to handle occasional transient errors during image layer extraction,
            // such as "UnexpectedEof" errors observed in gzip decompression. These issues may
            // be due to incomplete reads or temporary network failures. While the root cause
            // is unclear, this provides resilience. Be mindful of containerd's operation deadlines.
            const MAX_RETRIES: usize = 3;
            const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500); // 500ms delay
            let mut retries = 0;
            let mut generated_root_hash = None;
            while retries < MAX_RETRIES {
                match self
                    .fetch_and_process_layer(
                        upstream_name.clone(),
                        base_name.clone(),
                        digest_str,
                        layer_type,
                    )
                    .await
                {
                    Ok(root_hash) => {
                        generated_root_hash = Some(root_hash);
                        break;
                    } // Success; exit loop
                    Err(err) => {
                        retries += 1;
                        warn!(
                            "Failed to fetch/process layer (attempt {}/{}): {:?}",
                            retries, MAX_RETRIES, err
                        );
                        if retries >= MAX_RETRIES {
                            return Err(Status::unknown(format!(
                                "Failed to fetch/process layer after {} attempts: {:?}",
                                MAX_RETRIES, err
                            )));
                        }
                        info!("Retrying fetch/process layer...");
                        tokio::time::sleep(RETRY_DELAY).await; // Sleep before retrying
                    }
                }
            }
            let generated_root_hash = generated_root_hash
                .ok_or(Status::invalid_argument("failed to generate root hash"))?;

            // Store a label with the root hash so that we can recall it later
            // when mounting.
            match (root_hash, root_hash_sig) {
                (Some(root_hash), Some(root_hash_sig)) => {
                    if generated_root_hash != root_hash {
                        return Err(Status::invalid_argument(format!(
                            "the generated root hash {} does not match the expected root hash {}",
                            generated_root_hash, root_hash
                        )));
                    }
                    info!(
                        "found signature for layer {} with root hash {root_hash}: {root_hash_sig}",
                        digest_str
                    );
                    labels.insert(ROOT_HASH_LABEL.into(), root_hash);
                    labels.insert(ROOT_HASH_SIG_LABEL.into(), root_hash_sig);
                }
                _ => {
                    info!(
                        "signature not found, using generated root hash for layer {digest_str}: {generated_root_hash}"
                    );
                    labels.insert(ROOT_HASH_LABEL.into(), generated_root_hash);
                }
            }
        }

        // Move file to its final location and write the snapshot.
        {
            let mut store = self.store.write().await;
            let to = store
                .layer_path_to_write(&key)
                .map_err(|e| Status::unknown(format!("failed to create layer path: {e}")))?;
            trace!("Renaming from {:?} to {:?}", &snapshot_name, &to);
            tokio::fs::rename(snapshot_name, to).await?;
            store
                .write_snapshot(Kind::Committed, key, parent, labels)
                .map_err(|e| Status::internal(format!("failed to write snapshot: {e}")))?;
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
        let (layer_info, parent) = {
            // Needs to be in the closure to release the lock
            let mut store = self.store.write().await;
            let info = store.read_snapshot(&key).map_err(|e| {
                Status::unknown(format!("failed to read snapshot ({name}/{key}): {e}"))
            })?;
            if info.kind != Kind::Active {
                return Err(Status::failed_precondition(format!(
                    "snapshot {name} is not active"
                )));
            }

            let digest =
                info.labels
                    .get(TARGET_LAYER_DIGEST_LABEL)
                    .ok_or(Status::unimplemented(format!(
                "missing target layer digest label, no support for commiting arbitrary snapshots"
            )))?;

            let Some(image_ref_str) = labels.get(TARGET_IMAGE_REF_LABEL) else {
                return Err(Status::invalid_argument(
                    "missing target image ref label",
                ));
            };
            let Some(manifest_digest_str) = labels.get(TARGET_MANIFEST_DIGEST_LABEL) else {
                return Err(Status::invalid_argument(
                    "missing target manifest digest label",
                ));
            };

            // Skip loading signatures if they are already present. If a layer has multiple signatures, only the first loaded one will be used.
            // TODO: support the latest signature or signature filtering.
            if !store.has_signature(digest) {
                store.lazy_read_signatures(image_ref_str, manifest_digest_str).await.map_err(|e| {
                    Status::failed_precondition(format!("failed to read signatures: {e}"))
                })?;
            } else {
                debug!("Signature already exists for {digest}, skip loading the signature");
            }

            trace!("Looking up layer info for {digest}");
            let layer_info = store.get_info_from_digest(digest);

            (layer_info, info.parent)
        };

        self.prepare_image_layer(
            name,
            parent,
            labels,
            layer_info
                .as_ref()
                .map(|layer_info| layer_info.root_hash.clone()),
            layer_info
                .as_ref()
                .map(|layer_info| layer_info.signature.clone()),
        )
        .await
    }

    async fn usage_impl(&self, key: String) -> Result<Usage, Status> {
        let store = self.store.read().await;

        let info = store
            .read_snapshot(&key)
            .map_err(|e| Status::unknown(format!("failed to read snapshot ({key}): {e}")))?;
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
        let info = store.read_snapshot(&key).map_err(|e| {
            let error = format!("failed to read snapshot ({key}): {e}");
            error!("{error}");
            Status::unknown(error)
        })?;

        if info.kind != Kind::View && info.kind != Kind::Active {
            return Err(Status::failed_precondition(format!(
                "snapshot {key} is not active nor a view, but {info:?}",
                key = key,
                info = info
            )));
        }

        if info.labels.get(TARGET_LAYER_DIGEST_LABEL).is_some() {
            let extract_dir = store.extract_dir(&key);
            trace!("mounts(): snapshot: {}, pass extract_dir to containerd so that it unpacks the layer to extract_dir: {}", &info.name, extract_dir.to_string_lossy());
            Ok(vec![api::types::Mount {
                r#type: "bind".into(),
                source: extract_dir.to_string_lossy().into(),
                target: String::new(),
                options: Vec::new(),
            }])
        } else {
            trace!(
                "mounts(): snapshot: {}, ready to use, preparing itself and parents ",
                &info.name
            );
            store
                .mounts_from_snapshot(&info.parent, true)
                .map_err(|e| Status::failed_precondition(format!("failed to prepare mounts: {e}")))
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

        let name = store
            .snapshot_path(&key, false)
            .map_err(|e| Status::internal(format!("Failed to get snapshot path for {key}: {e}")))?;
        fs::remove_file(name)?;

        Ok(())
    }
}

#[tonic::async_trait]
impl Snapshotter for TarDevSnapshotter {
    type Error = Status;

    async fn stat(&self, key: String) -> Result<Info, Self::Error> {
        info!("stat({})", key);
        return self.store.read().await.read_snapshot(&key).map_err(|e| {
            let error = format!("failed to read snapshot ({key}): {e}");
            error!("stat() failed with: {:#?}", error);
            Status::unknown(error)
        });
    }

    async fn update(
        &self,
        info: Info,
        fieldpaths: Option<Vec<String>>,
    ) -> Result<Info, Self::Error> {
        info!("update({:?}, {:?})", info, fieldpaths);
        let error = "no support for updating snapshots";
        error!("update() failed with: {:#?}", error);
        Err(Status::unimplemented(error))
    }

    async fn usage(&self, key: String) -> Result<Usage, Self::Error> {
        debug!("usage({})", key);
        return self.usage_impl(key).await.map_err(|e| {
            error!("usage() failed with: {:#?}", e);
            e
        });
    }

    async fn mounts(&self, key: String) -> Result<Vec<api::types::Mount>, Self::Error> {
        debug!("mounts({})", key);
        return self.mounts_impl(key).await.map_err(|e| {
            error!("mounts() failed with: {:#?}", e);
            e
        });
    }

    async fn prepare(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Status> {
        info!("prepare({}, {}, {:?})", key, parent, labels);
        return {
            // There are two reasons for preparing a snapshot: to build an image and to actually use it
            // as a container image. We determine the reason by the presence of the snapshot-ref label.
            if labels.get(TARGET_LAYER_DIGEST_LABEL).is_some() {
                trace!("prepare(): prepare a staging dir for containerd tar data extraction");
                self.prepare_unpack_dir(key, parent, labels).await
            } else {
                trace!("prepare(): create active snapshot");
                self.store
                    .write()
                    .await
                    .prepare_snapshot_for_use(Kind::Active, key, parent, labels)
                    .map_err(|e| Status::unknown(format!("failed to prepare snapshot: {e}")))
            }
        }
        .map_err(|e| {
            error!("prepare() failed with: {:#?}", e);
            e
        });
    }

    async fn view(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Self::Error> {
        info!("view({}, {}, {:?})", key, parent, labels);
        return self
            .store
            .write()
            .await
            .prepare_snapshot_for_use(Kind::View, key, parent, labels)
            .map_err(|e| {
                let error = format!("failed to prepare snapshot: {e}");
                error!("view() failed with: {:#?}", error);
                Status::unknown(error)
            });
    }

    async fn commit(
        &self,
        name: String,
        key: String,
        labels: HashMap<String, String>,
    ) -> Result<(), Self::Error> {
        info!("commit({}, {}, {:?})", name, key, labels);
        return self.commit_impl(name, key, labels).await.map_err(|e| {
            error!("commit() failed with: {:#?}", e);
            e
        });
    }

    async fn remove(&self, key: String) -> Result<(), Self::Error> {
        info!("remove({})", key);
        return self.remove_impl(key).await.map_err(|e| {
            error!("remove() failed with: {:#?}", e);
            e
        });
    }

    type InfoStream = impl tokio_stream::Stream<Item = Result<Info, Self::Error>> + Send + 'static;
    async fn list(&self, _: String, _: Vec<String>) -> Result<Self::InfoStream, Self::Error> {
        info!("list()");
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
