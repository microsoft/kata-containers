use clap::Parser;
use fuser::MountOption;
use log::debug;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Error, ErrorKind, Read, Write};
use std::path::Path;
use zerocopy::byteorder::{LE, U32, U64};
use zerocopy::FromBytes;

mod fs;

// TODO: Remove this and import from dm-verity crate.
#[derive(Default, zerocopy::AsBytes, zerocopy::FromBytes, zerocopy::Unaligned)]
#[repr(C)]
pub struct VeritySuperBlock {
    pub data_block_size: U32<LE>,
    pub hash_block_size: U32<LE>,
    pub data_block_count: U64<LE>,
}

#[derive(Parser, Debug)]
struct Args {
    /// The source tarfs file.
    source: String,

    /// The directory on which to mount.
    directory: String,

    /// The filesystem type.
    #[arg(short)]
    r#type: Option<String>,

    /// The filesystem options.
    #[arg(short, long)]
    options: Vec<String>,
}

fn main() -> io::Result<()> {
    // return Err(Error::new(
    //     ErrorKind::PermissionDenied,
    //     "TEST",
    // ));
    env_logger::init();
    let args = Args::parse();
    let mountpoint = std::fs::canonicalize(&args.directory)?;
    let mut file = std::fs::File::open(&args.source)?;

    // Extract the file name from the input file path
    let input_file_name = Path::new(&args.source)
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid input file path"))?;
    let input_file_name_blk = format!("{}-blk", input_file_name.to_str().unwrap());

    // Check that the filesystem is tar.
    if let Some(t) = &args.r#type {
        if t != "tar" {
            debug!("Bad file system: {t}");
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "File system (-t) must be \"tar\"",
            ));
        }
    }

    // Parse all options.
    let mut options = Vec::new();
    for opts in &args.options {
        for opt in opts.split(',') {
            debug!("Parsing option {opt}");
            let fsopt = match opt {
                "dev" => MountOption::Dev,
                "nodev" => MountOption::NoDev,
                "suid" => MountOption::Suid,
                "nosuid" => MountOption::NoSuid,
                "ro" => MountOption::RO,
                "exec" => MountOption::Exec,
                "noexec" => MountOption::NoExec,
                "atime" => MountOption::Atime,
                "noatime" => MountOption::NoAtime,
                "dirsync" => MountOption::DirSync,
                "sync" => MountOption::Sync,
                "async" => MountOption::Async,
                "rw" => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "Tar file system are always read-only",
                    ));
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Unknown option ({opt})"),
                    ));
                }
            };
            options.push(fsopt);
        }
    }

    //let options = vec![MountOption::RO];

    // Construct the output file path in same tmpfs folder
    let output_file_path = Path::new("/run/kata-containers/sandbox/layers").join(input_file_name_blk);

    // Create an output file to write the data
    let mut output_file = File::create(&output_file_path)?;

    // Define a buffer to read data in chunks
    let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB buffer

    // Doing pretty much: dd if="/dev/mapper/xxx" of="/tmp/xxx"
    loop {
        // Read a chunk of data from the input file
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read == 0 {
            // End of file reached
            break;
        }

        // Write the chunk of data to the output file
        output_file.write_all(&buffer[..bytes_read])?;
    }

    output_file.sync_all()?;

    let output_file = OpenOptions::new()
        .read(true)
        .open(&output_file_path)?;

    let contents = unsafe { memmap::Mmap::map(&output_file)? };
    let vsb = VeritySuperBlock::read_from_prefix(&contents[contents.len() - 512..]).unwrap();

    debug!("Size: {}", contents.len());
    debug!("Data block size: {}", vsb.data_block_size);
    debug!("Hash block size: {}", vsb.hash_block_size);
    debug!("Data block count: {}", vsb.data_block_count);

    //let sb_offset = u64::from(vsb.data_block_size) * u64::from(vsb.data_block_count);
    let sb_offset = contents.len().try_into().unwrap();
    let tar = fs::Tar::new(contents, sb_offset)?;

    daemonize::Daemonize::new()
        .start()
        .map_err(|e| Error::new(ErrorKind::Other, e))?;

    fuser::mount2(tar, mountpoint, &options)
}
