# partition-identity

Find the ID of a device by its path, or find a device path by its ID.

> This crate was developed for inclusion in the [distinst](https://github.com/pop-os/distinst) project.

## Example

```rust
extern crate partition_identity;

use partition_identity::{PartitionID, PartitionSource};
use self::PartitionSource::*;
use std::env;
use std::process::exit;

fn main() {
    let mut args = env::args().skip(1);
    match args.next() {
        Some(arg) => match arg.as_str() {
            "from-path" => {
                let mut first = true;
                for device in args {
                    if ! first { println!() }
                    first = false;
                    println!("{}:", device);
                    println!("ID: {:?}", PartitionID::get_source(ID, &device).map(|id| id.id));
                    println!("Label: {:?}", PartitionID::get_source(Label, &device).map(|id| id.id));
                    println!("PartLabel: {:?}", PartitionID::get_source(PartLabel, &device).map(|id| id.id));
                    println!("PartUUID: {:?}", PartitionID::get_source(PartUUID, &device).map(|id| id.id));
                    println!("Path: {:?}", PartitionID::get_source(Path, &device).map(|id| id.id));
                    println!("UUID: {:?}", PartitionID::get_source(UUID, &device).map(|id| id.id));
                }
            }
            "by-uuid" => {
                for id in args {
                    let var = PartitionID::new_uuid(id.clone());
                    println!("{}: {:?}", id, var.get_device_path());
                }
            }
            "by-partuuid" => {
                for id in args {
                    let var = PartitionID::new_partuuid(id.clone());
                    println!("{}: {:?}", id, var.get_device_path());
                }
            }
            _ => {
                eprintln!("invalid subcommand: valid commansd: [from-path, by-uuid, by-partuuid, ]");
                exit(1);
            }
        }
        None => {
            eprintln!("must give subcommand: [from-path, by-uuid, by-partuuid, ]");
            exit(1);
        }
    }
}
```

### Example Output

```
$ example by-partuuid d1381cfb-739f-4963-ba02-695df6a42ca7
d1381cfb-739f-4963-ba02-695df6a42ca7: Some("/dev/sda2")
```

```
$ example by-uuid ed646eba-b8a3-4c79-8f93-5ee1a25c6ec3 92246269-7259-48e7-ae07-7e0b5027fd2d
ed646eba-b8a3-4c79-8f93-5ee1a25c6ec3: Some("/dev/dm-1")
92246269-7259-48e7-ae07-7e0b5027fd2d: Some("/dev/sdb3")
```

```
$ example from-path /dev/sda{1,2,3,4} /dev/sdb{1,2,3,4} /dev/mapper/{cryptdata,cryptswap,data,data-root}
/dev/sda1:
ID: Some("wwn-0x5002538d403d649a-part1")
Label: None
PartLabel: None
PartUUID: Some("0ff9334f-5649-439a-8138-1aa72e7c6af1")
Path: Some("pci-0000:00:17.0-ata-4-part1")
UUID: None

/dev/sda2:
ID: Some("wwn-0x5002538d403d649a-part2")
Label: None
PartLabel: None
PartUUID: Some("d1381cfb-739f-4963-ba02-695df6a42ca7")
Path: Some("pci-0000:00:17.0-ata-4-part2")
UUID: Some("0BE5-B90E")

/dev/sda3:
ID: Some("wwn-0x5002538d403d649a-part3")
Label: None
PartLabel: None
PartUUID: Some("9a1e3789-aa7a-4b1e-98bd-34cc3d1d7117")
Path: Some("pci-0000:00:17.0-ata-4-part3")
UUID: Some("221519d5-eb97-42d4-9b6d-32ccd3b8503e")

/dev/sda4:
ID: Some("wwn-0x5002538d403d649a-part4")
Label: None
PartLabel: None
PartUUID: Some("a87eb87a-6702-43dc-9e0b-b486d909422e")
Path: Some("pci-0000:00:17.0-ata-4-part4")
UUID: Some("b736abcd-d389-4074-b7dc-f3de743d9ae7")

/dev/sdb1:
ID: Some("usb-WD_Elements_25A2_575847314142373531363741-0:0-part1")
Label: None
PartLabel: None
PartUUID: Some("c9cc9475-a2ae-4b3f-93e1-5af45ceabfbf")
Path: Some("pci-0000:00:14.0-usb-0:4:1.0-scsi-0:0:0:0-part1")
UUID: Some("A590-DC0F")

/dev/sdb2:
ID: Some("usb-WD_Elements_25A2_575847314142373531363741-0:0-part2")
Label: None
PartLabel: Some("recovery")
PartUUID: Some("f52d3525-2057-460f-9b3f-46a8b59405f4")
Path: Some("pci-0000:00:14.0-usb-0:4:1.0-scsi-0:0:0:0-part2")
UUID: Some("A590-DBD6")

/dev/sdb3:
ID: Some("usb-WD_Elements_25A2_575847314142373531363741-0:0-part3")
Label: None
PartLabel: None
PartUUID: Some("8b623345-f890-4b47-a0a6-99a1c772a9bd")
Path: Some("pci-0000:00:14.0-usb-0:4:1.0-scsi-0:0:0:0-part3")
UUID: Some("92246269-7259-48e7-ae07-7e0b5027fd2d")

/dev/sdb4:
ID: Some("usb-WD_Elements_25A2_575847314142373531363741-0:0-part4")
Label: None
PartLabel: None
PartUUID: Some("f3108bcb-9f2d-43c4-a46b-3e2dd892948b")
Path: Some("pci-0000:00:14.0-usb-0:4:1.0-scsi-0:0:0:0-part4")
UUID: Some("b6639ce6-4bca-4193-9796-39e978fe24cf")

/dev/mapper/cryptdata:
ID: Some("lvm-pv-uuid-kAJFlt-88Gj-5JwA-T8da-MbAn-k6Jk-YxkB29")
Label: None
PartLabel: None
PartUUID: None
Path: None
UUID: None

/dev/mapper/cryptswap:
ID: Some("dm-uuid-CRYPT-PLAIN-cryptswap")
Label: None
PartLabel: None
PartUUID: None
Path: None
UUID: Some("fa5b7f8d-97c4-4152-8db6-5e054f03fb54")

/dev/mapper/data:
ID: None
Label: None
PartLabel: None
PartUUID: None
Path: None
UUID: None

/dev/mapper/data-root:
ID: Some("dm-uuid-LVM-JdyQEWdAYdvV0dxmGMj6f0poaYgJdR2FGMVKQt3bDCR0xSo1wRPUXYVInczK7ShF")
Label: None
PartLabel: None
PartUUID: None
Path: None
UUID: Some("ed646eba-b8a3-4c79-8f93-5ee1a25c6ec3")
```