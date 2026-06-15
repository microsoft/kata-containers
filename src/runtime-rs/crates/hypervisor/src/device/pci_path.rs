// Copyright (c) 2019-2023 Alibaba Cloud
// Copyright (c) 2019-2023 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::convert::TryFrom;

use anyhow::{anyhow, Context, Result};

// Tips:
// The Re-write `PciSlot` and `PciPath` with rust that it origins from `pcipath.go`:
//

// The PCI spec reserves 5 bits for slot number (a.k.a. device
// number), giving slots 0..31
const PCI_SLOT_BITS: u32 = 5;
const MAX_PCI_SLOTS: u32 = (1 << PCI_SLOT_BITS) - 1;

// The PCI spec reserves 3 bits for the function number (0..7), allowing
// up to 8 logical functions per PCI device slot. Most devices kata
// talks to are single-function (function 0), and the on-the-wire format
// omits the function in that case to stay backward-compatible (see the
// Display impl below).
const PCI_FUNCTION_BITS: u32 = 3;
const MAX_PCI_FUNCTIONS: u32 = (1 << PCI_FUNCTION_BITS) - 1;

// A PciSlot describes where one logical PCI function sits on a single
// bus: a device number (5 bits, 0..0x1f) plus a function number
// (3 bits, 0..7).
//
// Wire format: a single-function slot serialises as "ss" (e.g. "1f")
// to keep the historical slot-only form intact; a multi-function slot
// serialises as "ss.f" (e.g. "03.5"). Kata-agent's
// `pci::Path::from_str` accepts both ("00" is parsed as function 0).
//
// Multi-function packing is needed by the OpenVMM backend, where the
// PCIe root complex packs up to 8 root ports per device slot
// (see `GenericPcieRootComplex::new` in microsoft/openvmm:
// `vm/devices/pci/pcie/src/root.rs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PciSlot {
    pub device: u8,
    pub function: u8,
}

impl PciSlot {
    /// Construct a single-function PciSlot at the given device number.
    pub fn new(device: u8) -> PciSlot {
        PciSlot {
            device,
            function: 0,
        }
    }

    /// Construct a multi-function PciSlot. Used by the openvmm backend
    /// when packing many root ports into one device slot.
    pub fn with_function(device: u8, function: u8) -> Result<PciSlot> {
        if device as u32 > MAX_PCI_SLOTS {
            return Err(anyhow!(
                "PCI device number {} exceeds MAX: {}",
                device,
                MAX_PCI_SLOTS
            ));
        }
        if function as u32 > MAX_PCI_FUNCTIONS {
            return Err(anyhow!(
                "PCI function number {} exceeds MAX: {}",
                function,
                MAX_PCI_FUNCTIONS
            ));
        }
        Ok(PciSlot { device, function })
    }
}

impl std::fmt::Display for PciSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Function 0 is the historical default; omit it so the wire
        // format stays compatible with single-function callers and with
        // kata-agent's `SlotFn::from_str("xx")` shorthand.
        if self.function == 0 {
            write!(f, "{:02x}", self.device)
        } else {
            write!(f, "{:02x}.{:01x}", self.device, self.function)
        }
    }
}

impl TryFrom<&str> for PciSlot {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<PciSlot> {
        if s.is_empty() {
            return Err(anyhow!("string given is invalid."));
        }

        // Accept both "ss" (function defaults to 0) and "ss.f".
        let mut tokens = s.splitn(2, '.');
        let dev_str = tokens.next().unwrap();
        let func_str = tokens.next();

        if dev_str.is_empty() || dev_str.len() > 2 {
            return Err(anyhow!("string given is invalid."));
        }
        if let Some(f) = func_str {
            if f.is_empty() || f.len() > 1 {
                return Err(anyhow!("function token '{}' is invalid", f));
            }
        }

        let base = 16;
        let device = u8::from_str_radix(dev_str, base).context(format!(
            "convert device string '{}' to number with base {} failed.",
            dev_str, base
        ))?;
        if (device as u32) > MAX_PCI_SLOTS {
            return Err(anyhow!(
                "PCI device number {} exceeds MAX: {}",
                device,
                MAX_PCI_SLOTS
            ));
        }

        let function = match func_str {
            Some(f) => {
                let n = u8::from_str_radix(f, base).context(format!(
                    "convert function string '{}' to number with base {} failed.",
                    f, base
                ))?;
                if (n as u32) > MAX_PCI_FUNCTIONS {
                    return Err(anyhow!(
                        "PCI function number {} exceeds MAX: {}",
                        n,
                        MAX_PCI_FUNCTIONS
                    ));
                }
                n
            }
            None => 0,
        };

        Ok(PciSlot { device, function })
    }
}

impl TryFrom<u32> for PciSlot {
    type Error = anyhow::Error;

    fn try_from(v: u32) -> Result<PciSlot> {
        if v > MAX_PCI_SLOTS {
            return Err(anyhow!("value {:?} exceeds MAX: {:?}", v, MAX_PCI_SLOTS));
        }

        Ok(PciSlot {
            device: v as u8,
            function: 0,
        })
    }
}

// A PciPath describes where a PCI sits in a PCI hierarchy.
//
// Consists of a list of PCI slots, giving the slot of each bridge
// that must be traversed from the PCI root to reach the device,
// followed by the slot of the device itself.
//
// When formatted into a string is written as "xx/.../yy/zz". Here,
// zz is the slot of the device on its PCI bridge, yy is the slot of
// the bridge on its parent bridge and so forth until xx is the slot
// of the "most upstream" bridge on the root bus.
//
// If a device is directly connected to the root bus, which used in
// lightweight hypervisors, such as dragonball/firecracker/clh, and
// its PciPath.slots will contains only one PciSlot.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PciPath {
    // list of PCI slots
    pub slots: Vec<PciSlot>,
}

impl PciPath {
    pub fn new(slots: Vec<PciSlot>) -> Option<PciPath> {
        if slots.is_empty() {
            return None;
        }

        Some(PciPath { slots })
    }

    // device_slot to get the slot of the device on its PCI bridge
    pub fn get_device_slot(&self) -> Option<PciSlot> {
        self.slots.last().cloned()
    }

    // root_slot to get the slot of the "most upstream" bridge on the root bus
    pub fn get_root_slot(&self) -> Option<PciSlot> {
        self.slots.first().cloned()
    }
}

impl std::fmt::Display for PciPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Delegate to PciSlot::Display so that multi-function slots
        // serialise as "ss.f" while single-function slots stay "ss".
        write!(
            f,
            "{}",
            self.slots
                .iter()
                .map(|pci_slot| pci_slot.to_string())
                .collect::<Vec<String>>()
                .join("/")
        )
    }
}

// convert from u32
impl TryFrom<u32> for PciPath {
    type Error = anyhow::Error;

    fn try_from(slot: u32) -> Result<PciPath> {
        Ok(PciPath {
            slots: vec![PciSlot::try_from(slot).context("pci slot convert failed.")?],
        })
    }
}

impl TryFrom<&str> for PciPath {
    type Error = anyhow::Error;

    // method to parse a PciPath from a string
    fn try_from(path: &str) -> Result<PciPath> {
        if path.is_empty() {
            return Err(anyhow!("path given is empty."));
        }

        let mut pci_slots: Vec<PciSlot> = Vec::new();
        let slots: Vec<&str> = path.split('/').collect();
        for slot in slots {
            match PciSlot::try_from(slot) {
                Ok(s) => pci_slots.push(s),
                Err(e) => return Err(anyhow!("slot is invalid with: {:?}", e)),
            }
        }

        Ok(PciPath { slots: pci_slots })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_slot() {
        // min
        let pci_slot_01 = PciSlot::try_from("00");
        assert!(pci_slot_01.is_ok());
        // max
        let pci_slot_02 = PciSlot::try_from("1f");
        assert!(pci_slot_02.is_ok());

        // exceed
        let pci_slot_03 = PciSlot::try_from("20");
        assert!(pci_slot_03.is_err());

        // valid number
        let pci_slot_04 = PciSlot::try_from(1_u32);
        assert!(pci_slot_04.is_ok());
        assert_eq!(pci_slot_04.as_ref().unwrap().device, 1_u8);
        assert_eq!(pci_slot_04.as_ref().unwrap().function, 0_u8);
        let pci_slot_str = pci_slot_04.as_ref().unwrap().to_string();
        assert_eq!(
            pci_slot_str,
            format!("{:02x}", pci_slot_04.unwrap().device)
        );

        // max number
        let pci_slot_05 = PciSlot::try_from(31_u32);
        assert!(pci_slot_05.is_ok());
        assert_eq!(pci_slot_05.unwrap().device, 31_u8);

        // exceed and error
        let pci_slot_06 = PciSlot::try_from(32_u32);
        assert!(pci_slot_06.is_err());
    }

    #[test]
    fn test_pci_slot_multifunction() {
        // Multi-function constructor accepts function 0..7.
        let slot = PciSlot::with_function(0x03, 5).unwrap();
        assert_eq!(slot.device, 0x03);
        assert_eq!(slot.function, 5);

        // Wire format: non-zero function emits "ss.f".
        assert_eq!(slot.to_string(), "03.5");

        // Wire format: function 0 stays in the historical short form.
        assert_eq!(PciSlot::new(0x03).to_string(), "03");
        assert_eq!(PciSlot::with_function(0x03, 0).unwrap().to_string(), "03");

        // Parser accepts both forms and round-trips them.
        assert_eq!(PciSlot::try_from("03.5").unwrap(), slot);
        assert_eq!(PciSlot::try_from("03").unwrap(), PciSlot::new(0x03));

        // Function > 7 is rejected by both the constructor and the parser.
        assert!(PciSlot::with_function(0x03, 8).is_err());
        assert!(PciSlot::try_from("03.8").is_err());

        // Device > 0x1f is rejected by both the constructor and the parser.
        assert!(PciSlot::with_function(0x20, 0).is_err());
        assert!(PciSlot::try_from("20.0").is_err());

        // Malformed forms are rejected.
        assert!(PciSlot::try_from("03.").is_err());
        assert!(PciSlot::try_from("03.55").is_err());
        assert!(PciSlot::try_from(".5").is_err());
    }

    #[test]
    fn test_pci_patch() {
        let pci_path_0 = PciPath::try_from("01/0a/05");
        assert!(pci_path_0.is_ok());
        let pci_path_unwrap = pci_path_0.unwrap();
        assert_eq!(pci_path_unwrap.slots[0].device, 1);
        assert_eq!(pci_path_unwrap.slots[1].device, 10);
        assert_eq!(pci_path_unwrap.slots[2].device, 5);

        let pci_path_01 = PciPath::new(vec![
            PciSlot::new(1),
            PciSlot::new(10),
            PciSlot::new(5),
        ]);
        assert!(pci_path_01.is_some());
        let pci_path = pci_path_01.unwrap();
        let pci_path_02 = pci_path.to_string();
        assert_eq!(pci_path_02, "01/0a/05".to_string());

        let dev_slot = pci_path.get_device_slot();
        assert!(dev_slot.is_some());
        assert_eq!(dev_slot.unwrap().device, 5);

        let root_slot = pci_path.get_root_slot();
        assert!(root_slot.is_some());
        assert_eq!(root_slot.unwrap().device, 1);
    }

    #[test]
    fn test_pci_path_multifunction_roundtrip() {
        // PciPath with a multi-function root slot (e.g. OpenVMM root
        // port packed at device 0x03, function 5) round-trips through
        // Display and TryFrom<&str>.
        let mf_root = PciSlot::with_function(0x03, 5).unwrap();
        let endpoint = PciSlot::new(0);
        let path = PciPath::new(vec![mf_root, endpoint]).unwrap();
        assert_eq!(path.to_string(), "03.5/00");

        let parsed = PciPath::try_from("03.5/00").unwrap();
        assert_eq!(parsed, path);
    }
}
