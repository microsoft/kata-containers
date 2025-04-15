use clap::Parser;
use fuser::MountOption;
use log::{debug, info};
use std::io::{self, Error, ErrorKind};
use zerocopy::byteorder::{LE, U32, U64};
use zerocopy::FromBytes;
use std::fs::{OpenOptions, File};
use std::io::{Write, Read};
use chrono::Local;
use std::process;

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

fn get_parent_process_info() -> String {
    // Get our own PID
    let pid = process::id();
    
    // Get parent PID
    let mut ppid = 0;
    if let Ok(mut file) = File::open(format!("/proc/{}/stat", pid)) {
        let mut content = String::new();
        if file.read_to_string(&mut content).is_ok() {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() > 3 {
                ppid = parts[3].parse::<u32>().unwrap_or(0);
            }
        }
    }
    
    if ppid == 0 {
        return "Could not determine parent process".to_string();
    }
    
    // Get parent command line
    let mut parent_cmdline = String::new();
    if let Ok(mut file) = File::open(format!("/proc/{}/cmdline", ppid)) {
        let mut content = Vec::new();
        if file.read_to_end(&mut content).is_ok() {
            parent_cmdline = content.iter()
                .map(|&b| if b == 0 { ' ' } else { b as char })
                .collect();
        }
    }
    
    // Get parent process name
    let mut parent_name = String::new();
    if let Ok(mut file) = File::open(format!("/proc/{}/comm", ppid)) {
        let mut content = String::new();
        if file.read_to_string(&mut content).is_ok() {
            parent_name = content.trim().to_string();
        }
    }
    
    // Get process tree
    let mut process_tree = Vec::new();
    let mut current_pid = ppid;
    let max_depth = 5; // Limit to 5 levels to avoid infinite loops
    let mut depth = 0;
    
    while current_pid > 1 && depth < max_depth {
        let mut name = String::new();
        if let Ok(mut file) = File::open(format!("/proc/{}/comm", current_pid)) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                name = content.trim().to_string();
            }
        }
        
        process_tree.push(format!("{}({})", name, current_pid));
        
        // Get the parent of this process
        if let Ok(mut file) = File::open(format!("/proc/{}/stat", current_pid)) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                let parts: Vec<&str> = content.split_whitespace().collect();
                if parts.len() > 3 {
                    if let Ok(new_pid) = parts[3].parse::<u32>() {
                        if new_pid == current_pid {
                            break; // Avoid infinite loops
                        }
                        current_pid = new_pid;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
        
        depth += 1;
    }
    
    // Reverse the process tree to show root → ... → parent
    process_tree.reverse();
    
    format!(
        "Parent process: {} (PID: {})\nParent cmdline: {}\nProcess tree: {}",
        parent_name,
        ppid,
        parent_cmdline.trim(),
        process_tree.join(" → ")
    )
}

fn get_open_files_info() -> String {
    // Try to get information about all open file descriptors
    let mut result = String::new();
    
    let pid = process::id();
    let fd_dir = format!("/proc/{}/fd", pid);
    
    match std::fs::read_dir(fd_dir) {
        Ok(entries) => {
            result.push_str("Open file descriptors:\n");
            
            for entry in entries {
                if let Ok(entry) = entry {
                    let fd = entry.file_name().to_string_lossy().to_string();
                    let target = std::fs::read_link(entry.path()).ok()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    
                    result.push_str(&format!("  fd {}: {}\n", fd, target));
                }
            }
        },
        Err(_) => {
            result.push_str("Could not read file descriptors\n");
        }
    }
    
    result
}

fn main() -> io::Result<()> {
    // Initialize our custom logger
    init_custom_logger().unwrap();
    
    let args = Args::parse();
    
    info!("utarfs started with args: {:?}", args);
    info!("Current working directory: {:?}", std::env::current_dir().unwrap_or_default());
    info!("Environment variables: {:?}", std::env::vars().collect::<Vec<_>>());
    
    // Log parent process information
    info!("Parent process information: \n{}", get_parent_process_info());
    
    // Try to get open files information
    info!("Open files information: \n{}", get_open_files_info());
    
    // Try to get stack trace of parent if interesting
    let parent_process_info = get_parent_process_info();
    if parent_process_info.contains("containerd") || 
       parent_process_info.contains("snapshotter") || 
       parent_process_info.contains("kata") {
        
        info!("Attempting to get stack trace of parent process...");
        
        let ppid_str = parent_process_info.lines().next()
            .and_then(|line| line.split_whitespace().nth(3))
            .and_then(|pid_str| pid_str.trim_end_matches(')').parse::<u32>().ok())
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "unknown".to_string());
            
        // Try to capture stack trace using pstack if available
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("which pstack && pstack {} || echo 'pstack not available'", ppid_str))
            .output() {
            
            if let Ok(stack_output) = String::from_utf8(output.stdout) {
                info!("Parent process stack:\n{}", stack_output);
            }
        }
    }

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