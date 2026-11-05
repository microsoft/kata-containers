// Copyright (c) 2019 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::device::online_device;
use crate::linux_abi::*;
use crate::sandbox::Sandbox;
use crate::AGENT_CONFIG;
use slog::Logger;

use anyhow::{anyhow, Result};
use netlink_sys::{
    protocols as netlink_protocols, AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket,
};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;
use tracing::instrument;

const VDB_HOTPLUG_TEST_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct DeviceRemoval {
    root: String,
    slots: Vec<String>,
    prepared: bool,
    completed: tokio::sync::watch::Sender<bool>,
}

#[derive(Debug, Default)]
pub struct DeviceRemovalTracker {
    containers: HashMap<String, HashSet<String>>,
    devices: HashMap<String, DeviceRemoval>,
}

fn removal_identity(id: &str) -> Result<(String, String, Vec<String>)> {
    let (root, path) = crate::linux_abi::pcipath_from_dev_tree_path(id)?;
    let slots = path.iter().map(ToString::to_string).collect();
    Ok((
        format!("{root}/{path}"),
        create_pci_root_bus_path(root),
        slots,
    ))
}

impl DeviceRemovalTracker {
    // Register the original PCI identities before any device or storage resolution
    // can fail. Shared users must not reset an already prepared barrier.
    pub fn register(&mut self, req: &protocols::agent::CreateContainerRequest) -> Result<()> {
        let ids = req
            .devices
            .iter()
            .filter(|d| d.type_ == kata_types::device::DRIVER_BLK_PCI_TYPE)
            .map(|d| d.id.as_str())
            .chain(
                req.storages
                    .iter()
                    .filter(|s| {
                        s.driver == kata_types::device::DRIVER_BLK_PCI_TYPE
                            && !s.source.starts_with("/dev")
                    })
                    .map(|s| s.source.as_str()),
            );
        for id in ids {
            let (key, root, slots) = removal_identity(id)?;
            self.containers
                .entry(req.container_id.clone())
                .or_default()
                .insert(key.clone());
            let replace = self.devices.get(&key).is_none_or(|d| *d.completed.borrow());
            if replace {
                let (completed, _) = tokio::sync::watch::channel(false);
                self.devices.insert(
                    key,
                    DeviceRemoval {
                        root,
                        slots,
                        prepared: false,
                        completed,
                    },
                );
            }
        }
        Ok(())
    }

    pub fn prepare(&mut self, cid: &str) {
        if let Some(ids) = self.containers.remove(cid) {
            for id in ids {
                if let Some(device) = self.devices.get_mut(&id) {
                    device.prepared = true;
                }
            }
        }
    }

    fn process_remove(&mut self, event: &Uevent) {
        if event.subsystem != "pci" {
            return;
        }
        for device in self.devices.values_mut().filter(|d| d.prepared) {
            let Some(relative) = event.devpath.strip_prefix(&format!("{}/", device.root)) else {
                continue;
            };
            let parts: Vec<_> = relative.split('/').collect();
            if parts.len() == device.slots.len()
                && parts.iter().zip(&device.slots).all(|(part, slot)| {
                    part.rsplit_once(':').is_some_and(|(_, sf)| sf == slot)
                        && part.parse::<crate::pci::Address>().is_ok()
                })
            {
                device.completed.send_replace(true);
            }
        }
    }

    fn subscribe(&self, id: &str) -> Result<tokio::sync::watch::Receiver<bool>> {
        let (key, _, _) = removal_identity(id)?;
        let device = self
            .devices
            .get(&key)
            .ok_or_else(|| anyhow!("No device removal registered for {id}"))?;
        if !device.prepared {
            return Err(anyhow!("Device removal not prepared for {id}"));
        }
        Ok(device.completed.subscribe())
    }
}

pub async fn wait_for_device_removal(sandbox: &Arc<Mutex<Sandbox>>, id: &str) -> Result<()> {
    let mut completed = sandbox.lock().await.device_removals.subscribe(id)?;
    tokio::time::timeout(AGENT_CONFIG.hotplug_timeout, async {
        loop {
            if *completed.borrow_and_update() {
                return Ok(());
            }
            completed.changed().await.map_err(|e| anyhow!(e))?;
        }
    })
    .await
    .map_err(|_| anyhow!("Timeout waiting for PCI device removal {id}"))?
}

// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger().new(o!("subsystem" => "uevent"))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Uevent {
    pub action: String,
    pub devpath: String,
    pub devname: String,
    pub subsystem: String,
    seqnum: String,
    pub interface: String,
}

pub trait UeventMatcher: Sync + Send + Debug + 'static {
    fn is_match(&self, uev: &Uevent) -> bool;
}

impl Uevent {
    fn new(message: &str) -> Self {
        let mut msg_iter = message.split('\0');
        let mut event = Uevent::default();

        msg_iter.next(); // skip the first value
        for arg in msg_iter {
            let key_val: Vec<&str> = arg.splitn(2, '=').collect();
            if key_val.len() == 2 {
                match key_val[0] {
                    U_EVENT_ACTION => event.action = String::from(key_val[1]),
                    U_EVENT_DEV_NAME => event.devname = String::from(key_val[1]),
                    U_EVENT_SUB_SYSTEM => event.subsystem = String::from(key_val[1]),
                    U_EVENT_DEV_PATH => event.devpath = String::from(key_val[1]),
                    U_EVENT_SEQ_NUM => event.seqnum = String::from(key_val[1]),
                    U_EVENT_INTERFACE => event.interface = String::from(key_val[1]),
                    _ => (),
                }
            }
        }

        event
    }

    #[instrument]
    async fn process_add(&self, logger: &Logger, sandbox: &Arc<Mutex<Sandbox>>) {
        // Special case for memory hot-adds first
        let online_path = format!("{}/{}/online", SYSFS_DIR, self.devpath);
        if online_path.starts_with(SYSFS_MEMORY_ONLINE_PATH) {
            let _ = online_device(online_path.as_ref()).map_err(|e| {
                error!(
                    *logger,
                    "failed to online device";
                    "device" => &self.devpath,
                    "error" => format!("{}", e),
                )
            });
            return;
        }

        // Temporary fault injection: delay publication, not matching, so the
        // hotplug timeout can expire without being blocked by the sandbox lock.
        if self.subsystem == "block"
            && self.devname == "vdb"
            && self.devpath.starts_with("/devices/pci")
            && self.devpath.contains("/virtio")
            && self.devpath.ends_with("/block/vdb")
        {
            warn!(
                *logger,
                "Injecting hotplug event delay for /dev/vdb";
                "delay_seconds" => VDB_HOTPLUG_TEST_DELAY.as_secs(),
                "devpath" => &self.devpath,
            );
            tokio::time::sleep(VDB_HOTPLUG_TEST_DELAY).await;
        }

        let mut sb = sandbox.lock().await;

        // Record the event by sysfs path
        sb.uevent_map.insert(self.devpath.clone(), self.clone());

        // Notify watchers that are interested in the udev event.
        sb.uevent_watchers.iter_mut().for_each(move |watch| {
            if let Some((matcher, _)) = watch {
                if matcher.is_match(self) {
                    let (_, sender) = watch.take().unwrap();
                    let _ = sender.send(self.clone());
                }
            }
        })
    }

    #[instrument]
    async fn process_remove(&self, logger: &Logger, sandbox: &Arc<Mutex<Sandbox>>) {
        let mut sb = sandbox.lock().await;
        sb.uevent_map.remove(&self.devpath);
        if self.subsystem == "pci" {
            let prefix = format!("{}/", self.devpath);
            sb.uevent_map.retain(|path, _| !path.starts_with(&prefix));
        }
        sb.device_removals.process_remove(self);
    }

    #[instrument]
    async fn process(&self, logger: &Logger, sandbox: &Arc<Mutex<Sandbox>>) {
        if self.action == U_EVENT_ACTION_ADD {
            return self.process_add(logger, sandbox).await;
        } else if self.action == U_EVENT_ACTION_REMOVE {
            return self.process_remove(logger, sandbox).await;
        }
        debug!(*logger, "ignoring event"; "uevent" => format!("{:?}", self));
    }
}

#[instrument]
pub async fn wait_for_uevent(
    sandbox: &Arc<Mutex<Sandbox>>,
    matcher: impl UeventMatcher,
) -> Result<Uevent> {
    let logprefix = format!("Waiting for {:?}", matcher);

    info!(sl(), "{}", logprefix);
    let mut sb = sandbox.lock().await;
    for uev in sb.uevent_map.values() {
        if matcher.is_match(uev) {
            info!(sl(), "{}: found {:?} in uevent map", logprefix, &uev);
            return Ok(uev.clone());
        }
    }

    // If device is not found in the device map, hotplug event has not
    // been received yet, create and add channel to the watchers map.
    // The key of the watchers map is the device we are interested in.
    // Note this is done inside the lock, not to miss any events from the
    // global udev listener.
    let (tx, rx) = tokio::sync::oneshot::channel::<Uevent>();
    let idx = sb.uevent_watchers.len();
    sb.uevent_watchers.push(Some((Box::new(matcher), tx)));
    drop(sb); // unlock

    info!(sl(), "{}: waiting on channel", logprefix);

    let hotplug_timeout = AGENT_CONFIG.hotplug_timeout;

    let uev = match tokio::time::timeout(hotplug_timeout, rx).await {
        Ok(v) => v?,
        Err(_) => {
            let mut sb = sandbox.lock().await;
            let matcher = sb.uevent_watchers[idx].take().unwrap().0;

            return Err(anyhow!(
                "Timeout after {:?} waiting for uevent {:?}",
                hotplug_timeout,
                matcher
            ));
        }
    };

    info!(sl(), "{}: found {:?} on channel", logprefix, &uev);
    Ok(uev)
}

#[instrument]
pub async fn watch_uevents(
    sandbox: Arc<Mutex<Sandbox>>,
    mut shutdown: Receiver<bool>,
) -> Result<()> {
    let sref = sandbox.clone();
    let s = sref.lock().await;
    let logger = s.logger.new(o!("subsystem" => "uevent"));

    // Unlock the sandbox to allow a successful shutdown
    drop(s);

    info!(logger, "starting uevents handler");

    let mut socket;

    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            netlink_protocols::NETLINK_KOBJECT_UEVENT as libc::c_int,
        );
        socket = TokioSocket::from_raw_fd(fd);
    }

    socket.socket_mut().bind(&SocketAddr::new(0, 1))?;

    loop {
        select! {
            _ = shutdown.changed() => {
                info!(logger, "got shutdown request");
                break;
            }
            result = socket.recv_from_full() => {
                match result {
                    Err(e) => {
                        error!(logger, "failed to receive uevent"; "error" => format!("{}", e))
                    }
                    Ok((buf, addr)) => {
                        if addr.port_number() != 0 {
                            // not our netlink message
                            let err_msg = format!("{:?}", nix::Error::EBADMSG);
                            error!(logger, "receive uevent message failed"; "error" => err_msg);
                            continue;
                        }

                        let text = String::from_utf8(buf);
                        match text {
                            Err(e) => {
                                error!(logger, "failed to convert bytes to text"; "error" => format!("{}", e))
                            }
                            Ok(text) => {
                                let event = Uevent::new(&text);
                                info!(logger, "got uevent message"; "event" => format!("{:?}", event));
                                event.process(&logger, &sandbox).await;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// Used in the device module unit tests
#[cfg(test)]
pub(crate) fn spawn_test_watcher(sandbox: Arc<Mutex<Sandbox>>, uev: Uevent) {
    tokio::spawn(async move {
        loop {
            let mut sb = sandbox.lock().await;
            let uev = uev.clone();
            sb.uevent_watchers.iter_mut().for_each(move |watch| {
                if let Some((matcher, _)) = watch {
                    if matcher.is_match(&uev) {
                        let (_, sender) = watch.take().unwrap();
                        let _ = sender.send(uev.clone());
                    }
                }
            });

            drop(sb); // unlock
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::block_device_handler::VirtioBlkPciMatcher;

    fn block_request(cid: &str) -> protocols::agent::CreateContainerRequest {
        protocols::agent::CreateContainerRequest {
            container_id: cid.to_string(),
            devices: vec![protocols::agent::Device {
                id: "06".to_string(),
                type_: kata_types::device::DRIVER_BLK_PCI_TYPE.to_string(),
                ..Default::default()
            }],
            storages: vec![protocols::agent::Storage {
                driver: kata_types::device::DRIVER_BLK_PCI_TYPE.to_string(),
                source: "07".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn pci_remove() -> Uevent {
        Uevent {
            action: U_EVENT_ACTION_REMOVE.to_string(),
            subsystem: "pci".to_string(),
            devpath: format!("{}/0000:00:06.0", create_pci_root_bus_path("00")),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_device_removal_preprocessed_and_shared_cleanup() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Arc::new(Mutex::new(Sandbox::new(&logger).unwrap()));
        {
            let mut sb = sandbox.lock().await;
            let mut request = block_request("first");
            request.storages.push(protocols::agent::Storage {
                driver: kata_types::device::DRIVER_BLK_PCI_TYPE.to_string(),
                source: "/dev/vda".to_string(),
                ..Default::default()
            });
            sb.device_removals.register(&request).unwrap();
            assert!(sb.device_removals.subscribe("06").is_err());
            assert!(sb.device_removals.subscribe("08").is_err());
            sb.device_removals
                .register(&block_request("shared"))
                .unwrap();
            sb.device_removals.prepare("first");
            assert!(sb.device_removals.subscribe("07").is_ok());
        }
        pci_remove().process(&logger, &sandbox).await;
        sandbox.lock().await.device_removals.prepare("shared");
        sandbox.lock().await.device_removals.prepare("shared");
        wait_for_device_removal(&sandbox, "06").await.unwrap();
        wait_for_device_removal(&sandbox, "06.0").await.unwrap();
        {
            let mut sb = sandbox.lock().await;
            sb.device_removals.register(&block_request("new")).unwrap();
            assert!(sb.device_removals.subscribe("06").is_err());
            assert_eq!(sb.device_removals.devices.len(), 2);
            sb.device_removals.prepare("new");
        }
        assert!(wait_for_device_removal(&sandbox, "06").await.is_err());
    }

    #[tokio::test]
    async fn test_device_removal_requires_pci_function_and_retries_timeout() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Arc::new(Mutex::new(Sandbox::new(&logger).unwrap()));
        {
            let mut sb = sandbox.lock().await;
            sb.device_removals
                .register(&block_request("failed"))
                .unwrap();
            sb.device_removals.prepare("failed");
        }
        let mut child = pci_remove();
        child.subsystem = "block".to_string();
        child.devpath.push_str("/virtio5/block/vdb");
        child.process(&logger, &sandbox).await;
        assert!(wait_for_device_removal(&sandbox, "06").await.is_err());
        let (result, ()) = tokio::join!(wait_for_device_removal(&sandbox, "06"), async {
            tokio::task::yield_now().await;
            pci_remove().process(&logger, &sandbox).await;
        });
        result.unwrap();
    }

    #[tokio::test]
    async fn test_delayed_old_add_remove_new_add_barrier() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Arc::new(Mutex::new(Sandbox::new(&logger).unwrap()));
        sandbox
            .lock()
            .await
            .device_removals
            .register(&block_request("old"))
            .unwrap();
        let old = Uevent {
            action: U_EVENT_ACTION_ADD.to_string(),
            subsystem: "block".to_string(),
            devpath: "/devices/pci0000:00/0000:00:06.0/virtio5/block/vdb".to_string(),
            devname: "vdb".to_string(),
            ..Default::default()
        };
        let (old_result, ()) = tokio::join!(
            wait_for_uevent(&sandbox, VirtioBlkPciMatcher::new("/0000:00:06.0", "00")),
            old.process(&logger, &sandbox),
        );
        assert!(old_result.is_err());
        sandbox.lock().await.device_removals.prepare("old");
        assert!(wait_for_device_removal(&sandbox, "06").await.is_err());
        let mut child_remove = old.clone();
        child_remove.action = U_EVENT_ACTION_REMOVE.to_string();
        child_remove.process(&logger, &sandbox).await;
        pci_remove().process(&logger, &sandbox).await;
        wait_for_device_removal(&sandbox, "06").await.unwrap();
        sandbox
            .lock()
            .await
            .device_removals
            .register(&block_request("new"))
            .unwrap();
        let new = Uevent {
            devname: "vdc".to_string(),
            devpath: "/devices/pci0000:00/0000:00:06.0/virtio6/block/vdc".to_string(),
            ..old
        };
        new.process(&logger, &sandbox).await;
        let result = wait_for_uevent(&sandbox, VirtioBlkPciMatcher::new("/0000:00:06.0", "00"))
            .await
            .unwrap();
        assert_eq!(result.devname, "vdc");
    }

    #[tokio::test]
    async fn test_vdb_hotplug_delay_triggers_timeout() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Arc::new(Mutex::new(Sandbox::new(&logger).unwrap()));
        let uev = Uevent {
            action: U_EVENT_ACTION_ADD.to_string(),
            subsystem: "block".to_string(),
            devpath: "/devices/pci0000:00/0000:00:06.0/virtio5/block/vdb".to_string(),
            devname: "vdb".to_string(),
            ..Default::default()
        };
        let matcher = VirtioBlkPciMatcher::new("/0000:00:06.0", "00");
        assert!(AGENT_CONFIG.hotplug_timeout < VDB_HOTPLUG_TEST_DELAY);

        let start = tokio::time::Instant::now();
        let (result, ()) = tokio::join!(
            wait_for_uevent(&sandbox, matcher),
            uev.process(&logger, &sandbox),
        );
        assert!(start.elapsed() >= VDB_HOTPLUG_TEST_DELAY);
        assert!(result.unwrap_err().to_string().contains("Timeout after"));

        let sb = sandbox.lock().await;
        assert!(sb.uevent_watchers.iter().all(Option::is_none));
        assert_eq!(sb.uevent_map.get(&uev.devpath), Some(&uev));
    }

    #[tokio::test]
    async fn test_hotplug_delay_leaves_other_events_unchanged() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Arc::new(Mutex::new(Sandbox::new(&logger).unwrap()));
        for (devname, devpath) in [
            ("vda", "/devices/pci0000:00/0000:00:06.0/virtio5/block/vda"),
            ("vdc", "/devices/pci0000:00/0000:00:06.0/virtio5/block/vdc"),
            ("vdb", "/devices/platform/virtio-mmio/virtio5/block/vdb"),
            (
                "vdb1",
                "/devices/pci0000:00/0000:00:06.0/virtio5/block/vdb/vdb1",
            ),
        ] {
            let uev = Uevent {
                action: U_EVENT_ACTION_ADD.to_string(),
                subsystem: "block".to_string(),
                devpath: devpath.to_string(),
                devname: devname.to_string(),
                ..Default::default()
            };
            tokio::time::timeout(Duration::from_secs(1), uev.process(&logger, &sandbox))
                .await
                .unwrap();
            assert_eq!(sandbox.lock().await.uevent_map.get(devpath), Some(&uev));
        }

        let remove = Uevent {
            action: U_EVENT_ACTION_REMOVE.to_string(),
            subsystem: "block".to_string(),
            devpath: "/devices/pci0000:00/0000:00:06.0/virtio5/block/vdb".to_string(),
            devname: "vdb".to_string(),
            ..Default::default()
        };
        tokio::time::timeout(Duration::from_secs(1), remove.process(&logger, &sandbox))
            .await
            .unwrap();
    }

    #[derive(Debug, Clone, Copy)]
    struct AlwaysMatch();

    impl UeventMatcher for AlwaysMatch {
        fn is_match(&self, _: &Uevent) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_wait_for_uevent() {
        let uev = Uevent {
            action: crate::linux_abi::U_EVENT_ACTION_ADD.to_string(),
            subsystem: "test".to_string(),
            devpath: "/test/sysfs/path".to_string(),
            devname: "testdevname".to_string(),
            ..Default::default()
        };

        let matcher = AlwaysMatch();

        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Arc::new(Mutex::new(Sandbox::new(&logger).unwrap()));

        let mut sb = sandbox.lock().await;
        sb.uevent_map.insert(uev.devpath.clone(), uev.clone());
        drop(sb); // unlock

        let uev2 = wait_for_uevent(&sandbox, matcher).await;
        assert!(uev2.is_ok());
        assert_eq!(uev2.unwrap(), uev);

        let mut sb = sandbox.lock().await;
        sb.uevent_map.remove(&uev.devpath).unwrap();
        drop(sb); // unlock

        spawn_test_watcher(sandbox.clone(), uev.clone());

        let uev2 = wait_for_uevent(&sandbox, matcher).await;
        assert!(uev2.is_ok());
        assert_eq!(uev2.unwrap(), uev);
    }
}
