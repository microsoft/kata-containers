use std::collections::HashMap;
use crate::types::{CreateContainerInput, MountPoints};
use anyhow::{anyhow, Result};
use oci::{
    Box as ociBox, Linux as ociLinux, LinuxCapabilities as ociCapabilities,
    LinuxNamespace as ociLinuxNamespace, Mount as ociMount,
    Process as ociProcess, Root as ociRoot, Spec as ociSpec, User as ociUser, LinuxResources as ociLinuxResources
};
use slog::info;

// Default oci version string
const OCI_VERSION: &str = "1.1.0-rc.1";

// TO-DO: Test sandbox name
const TEST_SANDBOX_NAME: &str = "test-sandbox";
const TEST_CONTAINER_IMAGE_NAME: &str = "mcr.microsoft.com/mirror/docker/library/busybox:1.35";

// Default list of linux capabilities
static DEFAULT_CAPABILITIES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

// TO-DO: Priviledged container is not supported.
fn get_default_process() -> ociProcess {
    let default_capabilities = ociCapabilities{
        ambient: vec![],
        bounding: DEFAULT_CAPABILITIES.iter().map(|x| x.to_string()).collect::<Vec<String>>(),
        effective: DEFAULT_CAPABILITIES.iter().map(|x| x.to_string()).collect::<Vec<String>>(),
        inheritable: vec![],
        permitted: DEFAULT_CAPABILITIES.iter().map(|x| x.to_string()).collect::<Vec<String>>(),
    };

    ociProcess {
        terminal: false,
        console_size: Some(ociBox::default()),
        user: ociUser::default(),
        args: Vec::new(),
        env: Vec::new(),
        cwd: "/".to_string(),
        capabilities: Some(default_capabilities),
        rlimits: vec![],
        no_new_privileges: true,
        apparmor_profile: "".to_string(),
        oom_score_adj: Some(0),
        selinux_label: "".to_string(),
    }
}

// Helper function to return a set of defaul mounts
fn get_default_mounts(is_pause_container: bool) -> Vec<ociMount> {
    let mut mounts = vec![
        ociMount {
            destination: "/proc".to_string(),
            r#type: "proc".to_string(), 
            source: "proc".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
            ],
        },
        ociMount {
            destination: "/dev".to_string(),
            r#type: "tmpfs".to_string(),
            source: "tmpfs".to_string(),
            options: vec![
                "nosuid".to_string(),
                "strictatime".to_string(),
                "mode=755".to_string(),
                "size=65536k".to_string(),
            ],
        },
        ociMount {
            destination: "/dev/pts".to_string(),
            r#type: "devpts".to_string(),
            source: "devpts".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "newinstance".to_string(),
                "ptmxmode=0666".to_string(),
                "mode=0620".to_string(),
                "gid=5".to_string(),
            ],
        },
        // TO-DO: This needs to change.
        ociMount {
            destination: "/dev/shm".to_string(),
            r#type: "tmpfs".to_string(),
            source: "shm".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
                "size=65536k".to_string(),
            ],
        },
        ociMount {
            destination: "/dev/mqueue".to_string(),
            r#type: "mqueue".to_string(),
            source: "mqueue".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
            ],
        },
        ociMount {
            destination: "/sys".to_string(),
            r#type: "sysfs".to_string(),
            source: "sysfs".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "ro".to_string(),
            ],
        },
    ];

    if !is_pause_container {
        mounts.push(ociMount {
            destination: "/sys/fs/cgroup".to_string(),
            r#type: "cgroup".to_string(),
            source: "cgroup".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "relatime".to_string(),
                "ro".to_string(),
            ],
        });
    }

    mounts
}

fn get_linux_default_maskedpaths() -> Vec<String> {
    vec![
        "/proc/acpi".to_string(),
        "/proc/kcore".to_string(),
        "/proc/keys".to_string(),
        "/proc/latency_stats".to_string(),
        "/proc/timer_list".to_string(),
        "/proc/timer_stats".to_string(),
        "/proc/sched_debug".to_string(),
        "/proc/scsi".to_string(),
        "/sys/firmware".to_string(),
    ]
}

fn get_linux_default_readonlypaths() -> Vec<String> {
    vec![
        "/proc/asound".to_string(),
        "/proc/bus".to_string(),
        "/proc/fs".to_string(),
        "/proc/irq".to_string(),
        "/proc/sys".to_string(),
        "/proc/sysrq-trigger".to_string(),
    ]  
}

// Fix the ipc & uts namespace which are created when sandbox is created under /var/run/sandbox-ns
fn get_linux_namespaces() -> Vec<ociLinuxNamespace> {
    let mut namespaces = vec![ociLinuxNamespace {
        r#type: oci::PIDNAMESPACE.to_string(),
        path: "".to_owned(),
    }];

    // TO-DO: Look at this code
    namespaces.push(ociLinuxNamespace {
            r#type: oci::UTSNAMESPACE.to_string(),
            path: "".to_owned(),
    });

    namespaces.push(ociLinuxNamespace {
        r#type: oci::MOUNTNAMESPACE.to_string(),
        path: "".to_owned(),
    });

    namespaces.push(ociLinuxNamespace {
        r#type: oci::IPCNAMESPACE.to_string(),
        path: "".to_owned(),
    });
    // TO-DO: Handle network namespaces
    namespaces
}

fn get_linux_default_resources() -> ociLinuxResources {
    ociLinuxResources {
        devices: vec![],
        memory: None,
        cpu: Some(oci::LinuxCpu {
            shares: Some(2),
            quota: Some(0),
            period: Some(0),
            realtime_period: Some(0),
            realtime_runtime: Some(0),
            cpus: "".to_string(),
            mems: "".to_string(),
        }),
        pids: None,
        block_io: None,
        hugepage_limits: vec![],
        network: None,
        rdma: HashMap::new(),
    }
}

pub fn create_oci_process(is_pause_container: bool, cmds: &Vec<String>) -> ociProcess {
    info!(sl!(), "inside create oci process");
    // namespace = default
    // priviledged = false
    let mut process = get_default_process();
    
    // TO-DO: Handle add/drop capabilities for containers if provided

    // TO-DO: Handle Uids from image config layer or equivalent to runAsUser.
    if is_pause_container {
        process.user.uid = 65535;
        process.user.gid = 65535;
        process.user.additional_gids = vec![65535];
    } else {
        process.user.uid = 0;
        process.user.gid = 0;
        process.user.additional_gids = vec![0];
    }

    // Handle env
    // TO-DO: Set any additional environment variables like needed for any volumes mounted?
    process.env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    if !is_pause_container {
        process.env.push("HOSTNAME=$(host-name)".to_string());
    }

    // TO-DO: Handle commands/args from the image config layer.
    for command in cmds {
        process.args.push(command.clone());
    }

    process
}

// TO-DO: We pass the complete rootfs path here.
pub fn create_oci_root(path: &str) -> ociRoot {
    ociRoot {
        path: path.to_string(),
        readonly: false,
    }
}

pub fn create_oci_annotations(
     is_pause_container: bool,
     ns: &str,
     use_host_network: bool,
     sid: &str) -> HashMap<String, String> {

    let mut annots: HashMap<String, String> = HashMap::new();

    annots.insert("io.kubernetes.cri.sandbox-name".to_string(), TEST_SANDBOX_NAME.to_string());

    if !is_pause_container {
        // TO-DO: Remove hardcoded names
        annots.insert("io.kubernetes.cri.image-name".to_string(), TEST_CONTAINER_IMAGE_NAME.to_string());
        annots.insert("io.kubernetes.cri.container-name".to_string(), "test-container".to_owned());
        annots.insert("io.katacontainers.pkg.oci.container_type".to_string(), "pod_container".to_owned());
        annots.insert("io.kubernetes.cri.container-type".to_string(), "container".to_owned());
    }

    annots.insert("io.kubernetes.cri.sandbox-namespace".to_string(), ns.to_string());

    // TO-DO: See setting up netns for creating the pod sandbox
    if is_pause_container {
        let mut network_namespace = "^/var/run/netns/cni".to_string();
        if use_host_network {
            network_namespace += "test";
        }
        annots.insert("nerdctl/network-namespace".to_string(), network_namespace);

        annots.insert("io.katacontainers.pkg.oci.container_type".to_string(), "pod_sandbox".to_owned());
        annots.insert("io.kubernetes.cri.container-type".to_string(), "sandbox".to_owned());
    }

    annots.insert("io.kubernetes.cri.sandbox-id".to_string(), sid.to_string());

    // TO-DO: Set io.katacontainers.pkg.oci.bundle_path??
    annots
}

pub fn create_oci_mounts(is_pause_container: bool, i_mounts: &Vec<MountPoints>) -> Vec<ociMount> {

    let mut oci_mounts = get_default_mounts(is_pause_container);

    // TO-DO: No support for handling volume mounts for now.

    // add /etc/resolv.conf
    //     /etc/hosts
    //     /etc/hostname
    for mnts in i_mounts {
        if mnts.src.eq("/etc/resolv.conf") ||
           (!is_pause_container && (mnts.src.eq("/etc/hostname") ||
                                   mnts.src.eq("/etc/hosts")))  {
            let mut mounts = ociMount {
                destination: mnts.src.clone(),
                source: mnts.dest.clone(),
                r#type: "bind".to_owned(),
                options: vec![
                    "rbind".to_owned(),
                    "ro".to_owned(),
                    "nosuid".to_owned(),
                    "nodev".to_owned(),
                    "noexec".to_owned(),
                ]
            };
            if !mnts.options.is_empty() {
                let mut user_options = mnts.options.split(" ").map(|x| x.to_string()).collect::<Vec<String>>();
                mounts.options.append(&mut user_options);
            }

            oci_mounts.push(mounts);
        }
    }

    for mnts in i_mounts {
        for oci_mount in &mut oci_mounts {
            if oci_mount.source.eq(&mnts.src) {
                info!(sl!(), "Found user input for path, adjust the defaults");
                oci_mount.destination = mnts.dest.clone();
                if !mnts.options.is_empty() {
                    let mut user_options = mnts.options.split(" ").map(|x| x.to_string()).collect::<Vec<String>>();
                    oci_mount.options.append(&mut user_options);
                }
            }
        }
    }

    oci_mounts
}

pub fn create_oci_linux() -> ociLinux {
    ociLinux {
        uid_mappings: vec![],
        gid_mappings: vec![],
        sysctl: HashMap::new(),
        resources: Some(get_linux_default_resources()),
        cgroups_path: "".to_string(),
        namespaces: get_linux_namespaces(),
        devices: vec![],
        seccomp: None,
        rootfs_propagation: "".to_string(),
        masked_paths: get_linux_default_maskedpaths(),
        readonly_paths: get_linux_default_readonlypaths(),
        mount_label: "".to_string(),
        intel_rdt: None,
    }
}

pub fn generate_oci_spec(input: &CreateContainerInput) -> Result<ociSpec> {
    info!(sl!(), "inside generate oci spec");

    if input.container_id.is_empty() || input.sandbox_id.is_empty() || input.container_type.is_empty() {
        info!(sl!(), "Invalid inputs");
        return Err(anyhow!("Invalid CreateContainerInput"));
    }

    let is_pause_container = input.container_type.contains("pause");

    // generate Process
    let oci_process = create_oci_process(is_pause_container, &input.args);

    // generate Root path
    let oci_root = create_oci_root(&input.root_fs_path);

    // generate annotations
    let oci_annotations = create_oci_annotations(is_pause_container, "default", false, &input.sandbox_id);

    // generate mounts
    let oci_mounts = create_oci_mounts(is_pause_container, &input.mnt_options);

    // generate Linux
    let oci_linux = create_oci_linux();

    Ok(ociSpec {
        version: OCI_VERSION.to_string(),
        process: Some(oci_process),
        root: Some(oci_root),
        hostname: "".to_owned(),
        mounts: oci_mounts,
        hooks: None,
        annotations: oci_annotations,
        linux: Some(oci_linux),
        solaris: None,
        windows: None,
        vm: None,

    })
}
