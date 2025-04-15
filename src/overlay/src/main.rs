use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::{env::set_current_dir, process::Command};
use std::fs::OpenOptions;
use std::io::Write;

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

fn write_log(message: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/home/azureuser/kata-overlay-test.log")?;
    writeln!(file, "[{}] {}", std::process::id(), message)
}

const LAYER: &str = "io.katacontainers.fs-opt.layer=";
const LAYER_SRC_PREFIX: &str = "io.katacontainers.fs-opt.layer-src-prefix=";

#[derive(Debug)]
struct Layer {
    src: PathBuf,
    fs: String,
    opts: String,
}

fn parse_layers(args: &Args) -> io::Result<Vec<Layer>> {
    let mut layers = Vec::new();
    let mut prefix = Path::new("");

    for group in &args.options {
        for opt in group.split(',') {
            if let Some(p) = opt.strip_prefix(LAYER_SRC_PREFIX) {
                prefix = Path::new(p);
                continue;
            }

            let encoded = if let Some(e) = opt.strip_prefix(LAYER) {
                e
            } else {
                continue;
            };

            let decoded = general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
            let info = std::str::from_utf8(&decoded)
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;

            let mut fields = info.split(',');
            let src = if let Some(p) = fields.next() {
                if !p.is_empty() && p.as_bytes()[0] != b'/' {
                    prefix.join(Path::new(p))
                } else {
                    Path::new(p).to_path_buf()
                }
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Missing path from {info}"),
                ));
            };

            let fs = if let Some(f) = fields.next() {
                f.into()
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Missing filesystem type from {info}"),
                ));
            };

            let fs_opts = fields
                .filter(|o| !o.starts_with("io.katacontainers."))
                .fold(String::new(), |a, b| {
                    if a.is_empty() {
                        b.into()
                    } else {
                        format!("{a},{b}")
                    }
                });
            layers.push(Layer {
                src,
                fs,
                opts: fs_opts,
            });
        }
    }

    Ok(layers)
}

fn get_parent_process_info() -> String {
    // Get parent PID
    let pid = std::process::id();
    let mut ppid = 0;
    
    if let Ok(content) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() > 3 {
            ppid = parts[3].parse::<u32>().unwrap_or(0);
        }
    }
    
    // Get parent name
    let mut parent_name = String::new();
    if let Ok(content) = std::fs::read_to_string(format!("/proc/{}/comm", ppid)) {
        parent_name = content.trim().to_string();
    }
    
    let mut parent_cmdline = String::new();
    if let Ok(content) = std::fs::read_to_string(format!("/proc/{}/cmdline", ppid)) {
        parent_cmdline = content
            .split('\0')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
    }
    
    format!("Parent process: {} ({}), cmdline: {}", parent_name, ppid, parent_cmdline)
}

fn main() -> io::Result<()> {
    let args = &Args::parse();
    
    // Create a specific test log file
    write_log(&format!("TEST MODE: kata-overlay started with args: {:?}", args))?;
    write_log(&format!("TEST MODE: Current working directory: {:?}", std::env::current_dir()?))?;
    write_log(&get_parent_process_info())?;
    
    let layers = parse_layers(args)?;
    write_log(&format!("TEST MODE: Would mount layers: {:?}", layers))?;
    write_log(&format!("TEST MODE: Would mount to destination: {:?}", args.directory))?;
    
    // Instead of creating a tempdir and mounting, just create the destination directory
    // This ensures the directory exists but doesn't actually perform the mount
    std::fs::create_dir_all(&args.directory)?;
    
    if layers.len() == 1 {
        write_log("TEST MODE: Would have performed bind mount (single layer)")?;
    } else {
        write_log(&format!("TEST MODE: Would have performed overlay mount with {} layers", layers.len()))?;
    }
    
    write_log("TEST MODE: kata-overlay completed successfully - NO ACTUAL MOUNTING PERFORMED")?;
    
    // We return success without performing the actual mount
    Ok(())
}