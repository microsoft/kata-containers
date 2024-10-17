use base64::prelude::{Engine, BASE64_STANDARD};
use containerd_client::{services::v1::ReadContentRequest, tonic::Request, with_namespace, Client};
use containerd_snapshots::{api, Info, Kind, Snapshotter, Usage};
use log::{debug, info, trace};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::{collections::HashMap, fs, fs::OpenOptions, io, io::Seek, os::unix::ffi::OsStrExt};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tonic::Status;

const ROOT_HASH_LABEL: &str = "io.katacontainers.dm-verity.root-hash";
const TARGET_LAYER_DIGEST_LABEL: &str = "containerd.io/snapshot/cri.layer-digest";

struct Store {
    // the root directory where the snapshotter's data is stored
    root: PathBuf,
}

impl Store {
    // creates a new instance of `Store` with the provided root path.
    fn new(root: &Path) -> Self {
        Self { root: root.into() }
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
    /// Reads the metadata information of a snapshot from storage. It uses `serde_json` to deserialize the snapshot information from a JSON file.
    fn read_snapshot(&self, name: &str) -> Result<Info, Status> {
        let path = self.snapshot_path(name, false)?;
        let file = fs::File::open(path)?;
        serde_json::from_reader(file).map_err(|_| Status::unknown("unable to read snapshot"))
    }

    /// Writes to storage the given snapshot information.
    /// Writes snapshot information to storage as a JSON file. It uses `OpenOptions` to create a new file, ensuring that a snapshot with the same name does not already exist.
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
        serde_json::to_writer_pretty(file, &info)
            .map_err(|_| Status::internal("unable to write snapshot"))
    }

    /// Creates a new snapshot for use.
    /// This method is used to prepare a snapshot for use by a container. It verifies the parent chain of snapshots, ensuring they are all committed and consist of layers, before writing the new snapshot information.
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
        let mounts = self.mounts_from_snapshot(&parent)?;
        self.write_snapshot(kind, key, parent, labels)?;
        Ok(mounts)
    }

    /// The `mounts_from_snapshot` method is responsible for generating a list of mount points that are used to construct the overlay filesystem for a container. 
    /// An overlay filesystem allows multiple filesystems to be layered on top of one another, with the ability to write changes to a top, writable layer, while the lower layers remain read-only.
    fn mounts_from_snapshot(&self, parent: &str) -> Result<Vec<api::types::Mount>, Status> {
        const PREFIX: &str = "io.katacontainers.fs-opt";

        // Get chain of layers.
        // Layer Chain Construction
        let mut next_parent = Some(parent.to_string());
        let mut layers = Vec::new();
        let mut opts = vec![format!(
            "{PREFIX}.layer-src-prefix={}",
            self.root.join("layers").to_string_lossy()
        )];
        while let Some(p) = next_parent {
            // For each parent in the chain, the method reads the snapshot information using the `read_snapshot` method. 
            let info = self.read_snapshot(&p)?;
            // checks if the snapshot is committed, which is a necessary condition for the parent snapshot to be used in an overlay filesystem
            if info.kind != Kind::Committed {
                return Err(Status::failed_precondition(
                    "parent snapshot is not committed",
                ));
            }

            // looks for a root hash label in the snapshot's metadata. 
            // This root hash is crucial for integrity verification of the filesystem and is a specific requirement for the Kata Containers runtime, 
            // which uses a dm-verity root hash to ensure the filesystem is tamper-proof.
            let root_hash = if let Some(rh) = info.labels.get(ROOT_HASH_LABEL) {
                rh
            } else {
                return Err(Status::failed_precondition(
                    "parent snapshot has no root hash stored",
                ));
            };

            // constructs a string that includes the layer's name, its type (tar), and various options such as `block_device` and `root-hash`. 
            // This string is then base64 encoded using the `BASE64_STANDARD` engine. 
            // The encoded string is added to the `opts` vector with the prefix `io.katacontainers.fs-opt.layer`.
            let name = name_to_hash(&p);
            let layer_info = format!(
                "{name},tar,ro,{PREFIX}.block_device=file,{PREFIX}.is-layer,{PREFIX}.root-hash={root_hash}");
            layers.push(name);

            // adding each layer's information to the `opts` vector.
            opts.push(format!(
                "{PREFIX}.layer={}",
                BASE64_STANDARD.encode(layer_info.as_bytes())
            ));

            // The loop continues to traverse the parent chain until there are no more parents
            next_parent = (!info.parent.is_empty()).then_some(info.parent);
        }

        // After constructing the layer chain, the method adds additional options to the `opts` vector, 
        // such as `overlay-rw` to indicate a writable overlay layer and `lowerdir` to specify the lower, read-only layers.
        opts.push(format!("{PREFIX}.overlay-rw"));
        //  A colon-separated list of paths to the lower, read-only layers of the overlay filesystem
        opts.push(format!("lowerdir={}", layers.join(":")));

        // Finally, the method constructs a `Mount` struct from the `api::types::Mount` module, 
        // which includes the type of filesystem (`fuse3.kata-overlay`), the source (which is the root `/` in this case), 
        // the target (which is left empty here), and the options (`opts`) that were constructed throughout the method.
        Ok(vec![api::types::Mount {
            r#type: "fuse3.kata-overlay".into(),
            source: "/".into(),
            target: String::new(),
            options: opts,
        }])
    }
}

/// The snapshotter that creates tar devices.
pub(crate) struct TarDevSnapshotter {
    // wrapped in a `RwLock` for thread-safe mutable access
    store: RwLock<Store>,
    // points to the `containerd` socket
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

    /// This async method is responsible for preparing a directory for unpacking a layer by creating an active snapshot and returning a bind mount pointing to the extract directory.
    ///  It acquires a write lock on the `store`, creates an extraction directory for the snapshot, and writes an active snapshot entry to the store.
    /// Typically be called when a new layer needs to be added to a container's filesystem, such as when pulling a new image from a container registry and preparing it for use.
    ///  `key`: A `String` that uniquely identifies the snapshot.
    ///  `parent`: A `String` that identifies the parent snapshot (if any).
    ///  `labels`: A `HashMap` containing labels that provide metadata about the snapshot.
    /// It returns a `Result` that is either a vector of `api::types::Mount` (on success) or a `Status` (on error), which is a type used for error handling in gRPC services.
    async fn prepare_unpack_dir(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Status> {
        let extract_dir;
        {
            // acquiring a write lock on the `store`, which is necessary because it will be modifying the store's state by writing a new snapshot.
            let mut store = self.store.write().await;
            // This creates a directory where the layer associated with the snapshot can be extracted. The path to this directory is stored in the `extract_dir` variable.
            extract_dir = store.extract_dir_to_write(&key)?;
            // write a new snapshot with the `Kind::Active` state. This indicates that the snapshot is currently in use and may be modified. 
            // It passes the `key`, `parent`, and `labels` to this method.
            store.write_snapshot(Kind::Active, key, parent, labels)?;
        }
        // After releasing the write lock, the method constructs a `Mount` struct with the following fields:
        //  `"bind"`: This indicates that the mount is a bind mount, which means it will make the directory at `source` appear at the `target` location in the container's filesystem.
        //  `source`: This is set to the path of the `extract_dir` converted to a `String`. The `to_string_lossy` method is used to handle any potential non-UTF-8 sequences in the path, replacing them with a Unicode replacement character.
        //  `target`: This is left as an empty `String` for now. In the context of containerd, the target would be set later when the container runtime sets up the filesystem for a container.
        //  `options`: A vector containing a single `"bind"` string, specifying that this is a bind mount.
        Ok(vec![api::types::Mount {
            r#type: "bind".into(),
            source: extract_dir.to_string_lossy().into(),
            target: String::new(),
            options: vec!["bind".into()],
        }])
    }

    /// This async method retrieves a layer image from `containerd` using the provided digest. 
    /// It connects to `containerd` if not already connected and streams the layer content into a file.
    ///  This file can then be used for further operations, such as unpacking the layer and integrating it into the container's filesystem. 
    async fn get_layer_image(&self, fname: &PathBuf, digest: &str) -> Result<(), Status> {
        // creating a new file with the name specified by the `fname` argument. 
        // This file is where the layer image will be written to.
        let mut file = tokio::fs::File::create(fname).await?;
        // A `ReadContentRequest` is constructed with the `digest` of the layer to be fetched, 
        // the `offset` from where to start reading, and the `size` of the content to read. 
        // The `offset` and `size` are set to zero, indicating the desire to read the entire content from the beginning.
        let req = ReadContentRequest {
            digest: digest.to_string(),
            offset: 0,
            size: 0,
        };
        // The request is wrapped with a namespace using the `with_namespace!` macro, 
        // which scopes the request to a specific namespace in containerd, in this case, "k8s.io". 
        // Namespaces are a way to isolate resources within containerd.
        let req = with_namespace!(req, "k8s.io");

        // Enters a loop that attempts to use an existing containerd client connection or establish a new one if necessary. 
        // This loop is necessary because the client connection might not be established when the method is first called, 
        // or it might need to reconnect if the previous connection was lost.
        loop {
            let guard = self.containerd_client.read().await;
            let Some(client) = &*guard else {
                // checks if the `containerd_client` is already connected. If not, creates a new client connection to containerd using the `containerd_path`, 
                // and updates the `containerd_client` with the new connection.
                drop(guard);
                info!("Connecting to containerd at {}", self.containerd_path);
                let c = Client::from_path(&self.containerd_path)
                    .await
                    .map_err(|_| Status::unknown("unable to connect to containerd"))?;
                *self.containerd_client.write().await = Some(c);
                continue;
            };
            // Once a client connection is established, uses the client to send the `ReadContentRequest` to containerd and awaits the response. 
            // The response is a stream of messages, each containing a chunk of the layer image data.
            let mut c = client.content();
            let resp = c.read(req).await?;
            let mut stream = resp.into_inner();
            while let Some(chunk) = stream.message().await? {
                // For each chunk received in the stream, the method does the following:
                // checks if the chunk's offset is valid (non-negative).
                if chunk.offset < 0 {
                    debug!("Containerd reported a negative offset: {}", chunk.offset);
                    return Err(Status::invalid_argument("negative offset"));
                }
                // seeks to the specified offset in the file created earlier.
                file.seek(io::SeekFrom::Start(chunk.offset as u64)).await?;
                // writes the chunk data to the file at the correct offset.
                file.write_all(&chunk.data).await?;
            }

            return Ok(());
        }
    }

    /// Creates a new snapshot for an image layer.
    /// 
    /// This async method prepares a layer image by fetching it, 
    /// decompressing it, and appending an index and dm-verity tree. 
    /// It then moves the layer to its final location and writes a committed snapshot to the `store`.
    ///
    /// It downloads, decompresses, and creates the index for the layer before writing the new
    /// snapshot.
    async fn prepare_image_layer(
        &self,
        key: String,
        parent: String,
        mut labels: HashMap<String, String>,
    ) -> Result<(), Status> {
        // create staging directory
        let dir = self.store.read().await.staging_dir()?;

        {
            // retrieve the digest of the layer image from the `labels` hashmap using the key `TARGET_LAYER_DIGEST_LABEL`
            let Some(digest_str) = labels.get(TARGET_LAYER_DIGEST_LABEL) else {
                return Err(Status::invalid_argument(
                    "missing target layer digest label",
                ));
            };

            // constructs file paths for the layer image and its compressed form (with a `.gz` extension)
            let name = dir.path().join(name_to_hash(&key));
            let mut gzname = name.clone();
            gzname.set_extension("gz");
            trace!("Fetching layer image to {:?}", &gzname);
            //  calls `get_layer_image` to download the layer image from `containerd` and save it to the `gzname` path
            self.get_layer_image(&gzname, digest_str).await?;

            // TODO: Decompress in stream instead of reopening.
            // Decompress data.
            // spawns a blocking task to handle CPU-intensive operations, such as decompressing the image and appending the dm-verity tree.
            trace!("Decompressing {:?} to {:?}", &gzname, &name);
            let root_hash = tokio::task::spawn_blocking(move || -> io::Result<_> {
                let compressed = fs::File::open(&gzname)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&name)?;
                // uses the `flate2` crate to decompress the gzip file
                let mut gz_decoder = flate2::read::GzDecoder::new(compressed);
                std::io::copy(&mut gz_decoder, &mut file)?;

                // An index is appended to the decompressed file for faster access
                trace!("Appending index to {:?}", &name);
                file.rewind()?;
                tarindex::append_index(&mut file)?;

                //  A dm-verity tree is appended for integrity verification, and the root hash is calculated.
                trace!("Appending dm-verity tree to {:?}", &name);
                let root_hash = verity::append_tree::<Sha256>(&mut file)?;

                trace!("Root hash for {:?} is {:x}", &name, root_hash);
                Ok(root_hash)
            })
            .await
            .map_err(|_| Status::unknown("error in worker task"))??;

            // Store a label with the root hash so that we can recall it later when mounting.
            // After the root hash is calculated, it is formatted as a hexadecimal string.
            // This string is then inserted into the `labels` hashmap with the key `ROOT_HASH_LABEL` for later retrieval.
            labels.insert(ROOT_HASH_LABEL.into(), format!("{:x}", root_hash));
        }

        // Move file to its final location and write the snapshot.
        {
            // constructs the source (`from`) and destination (`to`) paths for the layer file.
            let from = dir.path().join(name_to_hash(&key));
            let mut store = self.store.write().await;
            let to = store.layer_path_to_write(&key)?;
            // uses `tokio::fs::rename` to move the file asynchronously.
            trace!("Renaming from {:?} to {:?}", &from, &to);
            tokio::fs::rename(from, to).await?;
            // writes a committed snapshot to the `store` with the updated `labels`, which now include the root hash.
            store.write_snapshot(Kind::Committed, key, parent, labels)?;
        }

        trace!("Layer prepared");
        Ok(())
    }
}

///
///  The `TarDevSnapshotter` implements the `Snapshotter` trait, providing methods like 
/// `stat`, `update`, `usage`, `mounts`, `prepare`, `view`, `commit`, `remove`, and `list`. 
/// These methods allow the snapshotter to interact with `containerd` to manage snapshots representing filesystem layers.
#[tonic::async_trait]
impl Snapshotter for TarDevSnapshotter {
    type Error = Status;

    /// Retrieves information about a specific snapshot.
    /// This method is used to retrieve metadata about a snapshot, such as its type (active, committed, or view), name, parent, and labels. 
    /// his information is stored in the snapshot's metadata file, which is why `read_snapshot` is called to read this file and deserialize the metadata into an `Info` struct.
    async fn stat(&self, key: String) -> Result<Info, Self::Error> {
        trace!("stat({})", key);
        self.store.read().await.read_snapshot(&key)
    }

    /// Updates the information of a snapshot (not implemented in this snapshotter).
    async fn update(
        &self,
        info: Info,
        fieldpaths: Option<Vec<String>>,
    ) -> Result<Info, Self::Error> {
        trace!("update({:?}, {:?})", info, fieldpaths);
        Err(Status::unimplemented("no support for updating snapshots"))
    }

    /// Reports the disk usage of a snapshot.
    ///  This method is used to report the disk usage of a snapshot, which includes the size of the snapshot in bytes and the number of inodes it uses. 
    /// To calculate the size, the method needs to know the path to the snapshot's layer file, which is part of the snapshot's metadata. 
    /// Therefore, it calls `read_snapshot` to obtain the `Info` struct that includes this path. Once it has the path, 
    /// it can open the file and seek to the end to determine its size. The inode count is a bit more complex to determine and is not fully implemented 
    /// in the provided code snippet (as indicated by the `TODO` comment).
    async fn usage(&self, key: String) -> Result<Usage, Self::Error> {
        trace!("usage({})", key);
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

    /// Provides the mount points for mounting a snapshot into a container's filesystem.
    async fn mounts(&self, key: String) -> Result<Vec<api::types::Mount>, Self::Error> {
        trace!("mounts({})", key);
        let store = self.store.read().await;
        // The `read_snapshot` method is called with the `key` to retrieve the snapshot's metadata. 
        let info = store.read_snapshot(&key)?;

        // checks if the snapshot is of kind `View` or `Active`. If it is neither, 
        // it returns an error with a message indicating that the snapshot must be active or a view to get mount points.
        if info.kind != Kind::View && info.kind != Kind::Active {
            return Err(Status::failed_precondition(
                "snapshot is not active nor a view",
            ));
        }

        //  checks if the snapshot's labels contain the `TARGET_LAYER_DIGEST_LABEL`. 
        // If it does, this indicates that the snapshot is associated with a layer image that needs to be unpacked.
        if info.labels.get(TARGET_LAYER_DIGEST_LABEL).is_some() {
            let extract_dir = store.extract_dir(&key);
            // It creates a `Mount` struct with the type set to `"bind"`, indicating a bind mount. 
            // The source is set to the path of the `extract_dir`, and the target is left empty (to be set later when the container runtime sets up the filesystem for a container). 
            // No additional options are provided in this case.
            Ok(vec![api::types::Mount {
                r#type: "bind".into(),
                source: extract_dir.to_string_lossy().into(),
                target: String::new(),
                options: Vec::new(),
            }])
        } else {
            // the snapshot does not have an associated layer image that needs to be unpacked. 
            // Instead, it needs to use the mounts from the snapshot's parent.
            store.mounts_from_snapshot(&info.parent)
        }
    }

    /// Prepares a new snapshot, either for building an image or for use as a container image.
    async fn prepare(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Status> {
        trace!("prepare({}, {}, {:?})", key, parent, labels);

        // There are two reasons for preparing a snapshot: to build an image and to actually use it
        // as a container image. We determine the reason by the presence of the snapshot-ref label.
        // when a new layer needs to be added to a container's filesystem, such as when pulling a new image from a container registry. 
        if labels.get(TARGET_LAYER_DIGEST_LABEL).is_some() {
            // the snapshot is being prepared for the purpose of unpacking a layer image
            // creates an extraction directory for the snapshot and writes an active snapshot entry to the store. 
            self.prepare_unpack_dir(key, parent, labels).await
        } // after the image layer has already been downloaded and unpacked
        else {
            // assumes the snapshot is being prepared for use as a container image
            //  verifying the parent chain of snapshots, ensuring they are all committed and consist of layers, 
            //  before writing the new snapshot information with the `Kind::Active` state. 
            //  This indicates that the snapshot is currently in use and may be modified. 
            self.store
                .write()
                .await
                .prepare_snapshot_for_use(Kind::Active, key, parent, labels)
        }
    }

    /// Similar to `prepare`, but for creating a read-only view of a snapshot.
    async fn view(
        &self,
        key: String,
        parent: String,
        labels: HashMap<String, String>,
    ) -> Result<Vec<api::types::Mount>, Self::Error> {
        trace!("view({}, {}, {:?})", key, parent, labels);
        // perform the necessary checks to ensure that the parent chain of snapshots is valid and that all ancestors are committed and consist of layers. 
        // It then writes the new snapshot information with the `Kind::View` state, indicating that the snapshot is a read-only view.
        self.store
            .write()
            .await
            .prepare_snapshot_for_use(Kind::View, key, parent, labels)
    }

    /// Commits an active snapshot, making it a permanent part of the layer history.
    /// This method finalizes an active snapshot, transitioning it to a committed state. 
    /// If the snapshot is associated with a layer image (as indicated by the presence of the `TARGET_LAYER_DIGEST_LABEL` label), it calls `prepare_image_layer` to handle the layer-specific processing. 
    /// If the snapshot is not associated with a layer image, the method returns an error indicating that committing arbitrary snapshots is not supported.
    async fn commit(
        &self,
        name: String,
        key: String,
        labels: HashMap<String, String>,
    ) -> Result<(), Self::Error> {
        trace!("commit({}, {}, {:?})", name, key, labels);

        let info;
        {
            let store = self.store.write().await;
            info = store.read_snapshot(&key)?;
            if info.kind != Kind::Active {
                return Err(Status::failed_precondition("snapshot is not active"));
            }
        }

        if info.labels.get(TARGET_LAYER_DIGEST_LABEL).is_some() {
            self.prepare_image_layer(name, info.parent, labels).await
        } else {
            Err(Status::unimplemented(
                "no support for commiting arbitrary snapshots",
            ))
        }
    }

    /// Removes a snapshot from the system.
    /// This method removes a snapshot from the system. It first reads the snapshot information to determine its kind. 
    /// If the snapshot is committed and associated with a layer image, it attempts to delete the corresponding layer file. 
    /// If the snapshot is active, it attempts to remove the directory where the layer was extracted. It then deletes the snapshot file itself.
    async fn remove(&self, key: String) -> Result<(), Self::Error> {
        trace!("remove({})", key);
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

    /// Lists all snapshots managed by the snapshotter.
    /// This method provides a stream of snapshot information, effectively listing all snapshots managed by the snapshotter. 
    /// It reads the snapshot directory and yields `Info` structs representing each snapshot.
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
