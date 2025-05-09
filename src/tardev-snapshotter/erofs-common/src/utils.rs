use anyhow::{anyhow, Context, Result};
use log::debug;
use std::path::Path;
use std::process::Command;
use std::fs::{File, OpenOptions};
use std::io::Write;
use crate::constants::EROFS_METADATA_UUID;
use crate::constants::EROFS_BLOCK_ALIGNMENT;

/// Validates the input file paths for erofs operations.
///
/// This function performs common validation checks on the input paths:
/// 1. Checks if paths are empty
/// 2. Validates that files exist
///
/// # Arguments
///
/// * `tar_path` - Path to the tar file
/// * `erofs_metadata_path` - Path to the erofs file
/// * `check_tar_exists` - Whether to check if tar file exists
/// * `check_erofs_metadata_exists` - Whether to check if erofs metadata file exists
///
/// # Returns
///
/// * `Result<()>` - Success or error
fn validate_input_paths(
    tar_path: &Path,
    erofs_metadata_path: &Path,
    check_tar_exists: bool,
    check_erofs_metadata_exists: bool,
) -> Result<()> {
    // Check if input parameters are empty
    if tar_path.as_os_str().is_empty() {
        return Err(anyhow!("Tar path is empty"));
    }

    if erofs_metadata_path.as_os_str().is_empty() {
        return Err(anyhow!("Erofs path is empty"));
    }

    // Check if tar file exists when required
    if check_tar_exists && !tar_path.exists() {
        return Err(anyhow!("Tar file does not exist: {:?}", tar_path));
    }

    // Check if erofs metadata file exists when required
    if check_erofs_metadata_exists && !erofs_metadata_path.exists() {
        return Err(anyhow!("Erofs metadata file does not exist: {:?}", erofs_metadata_path));
    }

    // If we're expecting the erofs metadata file NOT to exist (when creating a new one)
    // we should error if it already exists
    if !check_erofs_metadata_exists && erofs_metadata_path.exists() {
        return Err(anyhow!("Erofs metadata file already exists: {:?}", erofs_metadata_path));
    }

    Ok(())
}

/// Creates an erofs metadata file from a decompressed tar file.
///
/// This function:
/// 1. Takes a decompressed tar file path and output erofs metadata file path
/// 2. Executes the mkfs.erofs command with appropriate options
/// 3. Returns a Result indicating success or failure
///
/// # Arguments
///
/// * `decompressed_tar_path` - Path pointing to the decompressed tar file to process
/// * `erofs_metadata_path` - Path where the output erofs metadata file will be created
///
/// # Returns
///
/// * `Result<()>` - Success or error

pub fn create_erofs_metadata(
    decompressed_tar_path: &Path, 
    erofs_metadata_path: &Path,
) -> Result<()> {
    debug!(
        "Creating erofs metadata {:?} from {:?}",
        erofs_metadata_path, decompressed_tar_path
    );

    // Validate input paths - check tar exists but don't require erofs to exist yet
    validate_input_paths(decompressed_tar_path, erofs_metadata_path, true, false)?;

    let mut mkfs_cmd = Command::new("mkfs.erofs");
    mkfs_cmd.args([
        "--tar=i",                 // tar index mode
        "-T", "0",                 // Zero out unix time
        "--mkfs-time",             // Clear out mkfs time in superblock, keep per-inode mtime
        "-U", EROFS_METADATA_UUID, // UUID for erofs metadata
        "--aufs",                  // Convert OCI whiteouts/opaque to overlayfs metadata
        "--quiet",                 // Reduce output verbosity
        erofs_metadata_path.to_str().unwrap(),
        decompressed_tar_path.to_str().unwrap(),
    ]);
    
    // Execute the command
    let status = mkfs_cmd.status()
        .context("Failed to execute mkfs.erofs command")?;
    
    if !status.success() {
        return Err(anyhow!(
            "mkfs.erofs failed with status: {}",
            status.code().unwrap_or(-1)
        ));
    }

    // Verify the output file was created
    if !erofs_metadata_path.exists() {
        return Err(anyhow!("mkfs.erofs completed but output file was not created: {:?}", erofs_metadata_path));
    }
    
    Ok(())
}

/// Appends a decompressed tar file to an existing erofs metadata file and aligns the result.
///
/// This function:
/// 1. Opens the erofs metadata file in append mode
/// 2. Opens the decompressed tar file for reading
/// 3. Copies the entire tar file contents to the end of the erofs metadata
/// 4. Aligns the resulting file to the specified block size
///
/// # Arguments
///
/// * `decompressed_tar_path` - Path to the decompressed tar file to append
/// * `erofs_metadata_path` - Path to the erofs metadata file where the tar will be appended
///
/// # Returns
///
/// * `Result<>` - Success or error
pub fn append_tar_to_erofs_metadata(
    decompressed_tar_path: &Path,
    erofs_metadata_path: &Path
) -> Result<()> {
    debug!(
        "Appending decompressed tar file {:?} to erofs metadata {:?}",
        decompressed_tar_path, erofs_metadata_path
    );

    // Validate input paths - both files must exist
    validate_input_paths(decompressed_tar_path, erofs_metadata_path, true, true)?;

    // Open erofs file in append mode
    let mut erofs_file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(erofs_metadata_path)
        .context("Failed to open erofs metadata file for appending")?;

    // Open tar file for reading
    let mut tar_file = File::open(decompressed_tar_path)
        .context("Failed to open decompressed tar file for reading")?;

    // Append tar file to erofs
    std::io::copy(&mut tar_file, &mut erofs_file)
        .context("Failed to append decompressed tar file to erofs metadata")?;

    // Get current file size
    let mut erofs_file_size = erofs_file.metadata()
        .context("Failed to get erofs file metadata")?
        .len();

    // Align the file size to block alignment
    let alignment = EROFS_BLOCK_ALIGNMENT;
    let padding = (alignment - (erofs_file_size % alignment)) % alignment;

    if padding > 0 {
        let padding_bytes = vec![0u8; padding as usize];
        erofs_file.write_all(&padding_bytes)
            .context("Failed to write padding bytes")?;
        debug!("Added {} bytes of padding to align to {} bytes", padding, alignment);
        
        // Update file size after padding
        erofs_file_size = erofs_file_size + padding;
    }

    // Close the tar file
    drop(tar_file);

    // Flush to ensure all changes are written to disk
    // Close the erofs file
    erofs_file.flush()
        .context("Failed to flush erofs file changes")?;
    drop(erofs_file);

    debug!("Final size of erofs metadata + tar: {} bytes", erofs_file_size);
    
    Ok(())
}