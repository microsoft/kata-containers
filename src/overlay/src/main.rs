use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::{env::set_current_dir, process::Command};
use std::fs::{OpenOptions, File};
use std::io::{Write, Read};
use std::process;

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
        .open("/home/azureuser/kata-overlay.log")?;
    writeln!(file, "[{}] {}", std::process::id(), message)
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

struct Unmounter(Vec<String>, tempfile::TempDir);
impl Drop for Unmounter {
    fn drop(&mut self) {
        for n in &self.0 {
            let p = self.1.path().join(n);
            match Command::new("umount").arg(&p).status() {
                Err(e) => eprintln!("Unable to run umount command: {e}"),
                Ok(s) => {
                    if !s.success() {
                        eprintln!("Unable to unmount {:?}: {s}", p);
                    }
                }
            }
        }
    }
}

fn main() -> io::Result<()> {
    let args = &Args::parse();
    
    // Log startup information
    write_log(&format!("kata-overlay started with args: {:?}", args))?;
    write_log(&format!("Current working directory: {:?}", std::env::current_dir()?))?;
    write_log(&format!("Environment variables: {:?}", std::env::vars().collect::<Vec<_>>()))?;
    
    // Log parent process information
    write_log(&get_parent_process_info())?;
    
    // Try to get stack trace from parent if it's a process we're interested in
    let parent_process_info = get_parent_process_info();
    if parent_process_info.contains("containerd") || parent_process_info.contains("snapshotter") {
        write_log("Attempting to get stack trace of parent process...")?;
        
        let ppid_str = parent_process_info.lines().next()
            .and_then(|line| line.split_whitespace().nth(3))
            .and_then(|pid_str| pid_str.trim_end_matches(')').parse::<u32>().ok())
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "unknown".to_string());
            
        // Try to capture stack trace using pstack if available
        if let Ok(output) = Command::new("sh")
            .arg("-c")
            .arg(format!("which pstack && pstack {} || echo 'pstack not available'", ppid_str))
            .output() {
            
            if let Ok(stack_output) = String::from_utf8(output.stdout) {
                write_log(&format!("Parent process stack:\n{}", stack_output))?;
            }
        }
    }
    
    let layers = parse_layers(args)?;
    let mut unmounter = Unmounter(Vec::new(), tempfile::tempdir()?);

    write_log(&format!("Parsed layers: {:?}", layers))?;

    // Mount all layers.
    //
    // We use the `mount` command instead of a syscall because we want leverage the additional work
    // that `mount` does, for example, using helper binaries to mount.
    write_log("Beginning layer mounting")?;
    for (i, layer) in layers.iter().enumerate() {
        let n = i.to_string();
        let p = unmounter.1.path().join(&n);
        std::fs::create_dir_all(&p)?;
        println!("Mounting {:?} to {:?}", layer.src, p);

        let status = Command::new("mount")
            .arg(&layer.src)
            .arg(&p)
            .arg("-t")
            .arg(&layer.fs)
            .arg("-o")
            .arg(&layer.opts)
            .status()?;
        if !status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to mount {:?}: {status}", &layer.src),
            ));
        }

        unmounter.0.push(n);
    }

    // Mount the overlay if we have multiple layers, otherwise do a bind-mount.
    let mp = std::fs::canonicalize(&args.directory)?;
    write_log(&format!("Mounting to destination: {:?}", mp))?;
    
    if unmounter.0.len() == 1 {
        write_log("Performing bind mount (single layer)")?;
        let p = unmounter.1.path().join(unmounter.0.first().unwrap());
        let status = Command::new("mount")
            .arg(&p)
            .arg(&mp)
            .args(&["-t", "bind", "-o", "bind"])
            .status()?;
        if !status.success() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to bind mount: {status}"),
            ));
        }
        write_log(&format!("Bind mount result: {}", status))?;
    } else {
        let saved = std::env::current_dir()?;
        set_current_dir(unmounter.1.path())?;
        write_log(&format!("Performing overlay mount with {} layers", unmounter.0.len()))?;

        let lowerdirs = unmounter.0.join(":");
        let opts = format!("lowerdir={}", lowerdirs);
    
        // Replace the mount(8) tool with nix::mount to address the limitation of FSCONFIG_SET_STRING,
        // which has a 256-byte limit and cannot accommodate multiple lowerdir entries.
        nix::mount::mount(
            Some("overlay"),
            &mp,
            Some("overlay"),
            nix::mount::MsFlags::empty(),
            Some(opts.as_str()),
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to mount overlay to {}: {}", mp.display(), e),
            )
        })?;
        write_log("Overlay mount successful")?;
    
        set_current_dir(saved)?;
    }
    
    write_log("kata-overlay completed successfully")?;
    Ok(())
}