// Common constants for use by both tardev-snapshotter and sign-oci-layer-root-hashes modules.

/// OCI label for dm-verity root hash.
pub const ROOT_HASH_LABEL: &str = "io.katacontainers.dm-verity.root-hash";

/// OCI label for dm-verity root hash signature.
pub const ROOT_HASH_SIG_LABEL: &str = "io.katacontainers.dm-verity.root-hash-sig";

/// OCI label for image reference name.
pub const IMAGE_NAME_LABEL: &str = "image.ref.name";

/// OCI label for image layer digest.
pub const IMAGE_LAYER_DIGEST_LABEL: &str = "image.layer.digest";

/// OCI label for image layer root hash.
pub const IMAGE_LAYER_ROOT_HASH_LABEL: &str = "image.layer.root_hash";

/// OCI label for image layer signature.
pub const IMAGE_LAYER_SIGNATURE_LABEL: &str = "image.layer.signature";

/// Artifact type for signature manifests.
pub const SIGNATURE_ARTIFACT_TYPE: &str = "application/vnd.oci.mt.pkcs7";

/// Media type for signature blobs.
pub const SIGNATURE_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.erofs.sig";

/// Default file name for signature blobs.
pub const SIGNATURE_FILE_NAME: &str = "signature.blob.name";

/// Digest for the canonical empty config blob ({}).
pub const EMPTY_CONFIG_DIGEST: &str = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// The mediatype for a layer.
pub const IMAGE_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

/// The mediatype for a layer that is gzipped.
pub const IMAGE_LAYER_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// The mediatype that Docker uses for a layer that is tarred.
pub const IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE: &str = "application/vnd.docker.image.rootfs.diff.tar";

/// The mediatype that Docker uses for a layer that is gzipped.
pub const IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE: &str =
    "application/vnd.docker.image.rootfs.diff.tar.gzip";
