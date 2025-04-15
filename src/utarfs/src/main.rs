use clap::Parser;
use fuser::MountOption;
use log::{debug, info};
use std::io::{self, Error, ErrorKind};
use zerocopy::byteorder::{LE, U32, U64};
use zerocopy::FromBytes;
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

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

// Custom logger implementation
struct FileLogger;

static LOGGER: FileLogger = FileLogger;

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("/home/azureuser/utarfs.log")
                .unwrap_or_else(|_| panic!("Failed to open log file"));
            
            writeln!(file, "[{}] {} - {}: {}", 
                std::process::id(),
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.args()
            ).unwrap_or_else(|_| panic!("Failed to write to log file"));
        }
    }

    fn flush(&self) {}
}

fn init_custom_logger() -> Result<(), log::SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::Trace))
}

fn main() -> io::Result<()> {
    // Initialize our custom logger instead of env_logger
    init_custom_logger().unwrap();
    
    let args = Args::parse();
    
    info!("utarfs started with args: {:?}", args);
    info!("Current working directory: {:?}", std::env::current_dir().unwrap_or_default());
    info!("Environment variables: {:?}", std::env::vars().collect::<Vec<_>>());

    let mountpoint = std::fs::canonicalize(&args.directory)?;
    let file = std::fs::File::open(&args.source)?;

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

    let contents = unsafe { memmap::Mmap::map(&file)? };
    let vsb = VeritySuperBlock::read_from_prefix(&contents[contents.len() - 512..]).unwrap();

    debug!("Size: {}", contents.len());
    debug!("Data block size: {}", vsb.data_block_size);
    debug!("Hash block size: {}", vsb.hash_block_size);
    debug!("Data block count: {}", vsb.data_block_count);

    let sb_offset = u64::from(vsb.data_block_size) * u64::from(vsb.data_block_count);
    let tar = fs::Tar::new(contents, sb_offset)?;

    // Add one more log message before daemonizing
    info!("utarfs about to daemonize and mount at {:?}", mountpoint);

    daemonize::Daemonize::new()
        .start()
        .map_err(|e| Error::new(ErrorKind::Other, e))?;

    fuser::mount2(tar, mountpoint, &options)
}