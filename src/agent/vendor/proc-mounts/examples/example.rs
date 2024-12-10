extern crate proc_mounts;

use proc_mounts::{MountIter, SwapIter};
use std::io;

fn main() -> io::Result<()> {
    println!("# Active Mounts");
    for mount in MountIter::new()? {
        match mount {
            Ok(mount) => println!("{:?}: {:?}", mount.source, mount.dest),
            Err(why) => eprintln!("error reading mount: {}", why),
        }
    }

    println!("# Active Swaps");
    for swap in SwapIter::new()? {
        println!("{:#?}", swap);
    }

    println!("# Active Fstab Mounts");
    for mount in MountIter::new_from_file("/etc/fstab")? {
        match mount {
            Ok(mount) => println!("{:?}: {:?}", mount.source, mount.dest),
            Err(why) => eprintln!("error reading mount: {}", why),
        }
    }

    Ok(())
}
