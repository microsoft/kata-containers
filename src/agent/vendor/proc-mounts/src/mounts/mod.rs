mod info;
mod iter;
mod list;
mod tab;

pub use self::{info::*, iter::*, list::*, tab::*};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    const SAMPLE: &str = r#"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
udev /dev devtmpfs rw,nosuid,relatime,size=16420480k,nr_inodes=4105120,mode=755 0 0
tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3291052k,mode=755 0 0
/dev/sda2 / ext4 rw,noatime,errors=remount-ro,data=ordered
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0
/dev/sda1 /boot/efi vfat rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro 0 0
/dev/sda6 /mnt/data ext4 rw,noatime,data=ordered 0 0"#;

    #[test]
    fn source_mounted_at() {
        let mounts = MountList::parse_from(SAMPLE.lines()).unwrap();
        assert!(mounts.source_mounted_at("/dev/sda2", "/"));
        assert!(mounts.source_mounted_at("/dev/sda1", "/boot/efi"));
    }

    #[test]
    fn mounts() {
        let mounts = MountList::parse_from(SAMPLE.lines()).unwrap();

        assert_eq!(
            mounts.get_mount_by_source(Path::new("/dev/sda1")).unwrap(),
            &MountInfo {
                source:  PathBuf::from("/dev/sda1"),
                dest:    PathBuf::from("/boot/efi"),
                fstype:  "vfat".into(),
                options: vec![
                    "rw".into(),
                    "relatime".into(),
                    "fmask=0077".into(),
                    "dmask=0077".into(),
                    "codepage=437".into(),
                    "iocharset=iso8859-1".into(),
                    "shortname=mixed".into(),
                    "errors=remount-ro".into(),
                ],
                dump:    0,
                pass:    0,
            }
        );

        let path = &Path::new("/");
        assert_eq!(
            mounts.destination_starts_with(path).map(|m| m.dest.clone()).collect::<Vec<PathBuf>>(),
            vec![
                PathBuf::from("/sys"),
                PathBuf::from("/proc"),
                PathBuf::from("/dev"),
                PathBuf::from("/run"),
                PathBuf::from("/"),
                PathBuf::from("/sys/fs/fuse/connections"),
                PathBuf::from("/boot/efi"),
                PathBuf::from("/mnt/data")
            ]
        );
    }
}
