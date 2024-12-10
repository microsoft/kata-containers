extern crate partition_identity;

use partition_identity::{PartitionID, PartitionIdentifiers};
use std::env;
use std::process::exit;

fn main() {
    let mut args = env::args().skip(1);
    match args.next() {
        Some(arg) => match arg.as_str() {
            "from-path" => {
                let mut first = true;
                for device in args {
                    if !first {
                        println!()
                    }
                    first = false;
                    println!("{}:", device);
                    println!("{:#?}", PartitionIdentifiers::from_path(device));
                }
            }
            "by-id" => {
                for id in args {
                    let var = PartitionID::new_id(id.clone());
                    println!("{}: {:?}", id, var.get_device_path());
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
            "detect-by" => {
                for id in args {
                    let id = match PartitionID::from_disk_by_path(&id) {
                        Ok(id) => id,
                        Err(why) => {
                            eprintln!("{}: {}", id, why);
                            exit(1);
                        }
                    };

                    println!("{:?} = {:?}", id, id.get_device_path());
                }
            }
            _ => {
                eprintln!(
                    "invalid subcommand: valid commansd: [from-path, by-uuid, by-partuuid, ]"
                );
                exit(1);
            }
        },
        None => {
            eprintln!("must give subcommand: [from-path, by-uuid, by-partuuid, ]");
            exit(1);
        }
    }
}
