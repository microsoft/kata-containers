// Copyright Red Hat.
//
// SPDX-License-Identifier: Apache-2.0
//

package types

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// The PCI spec reserves 5 bits for slot number (a.k.a. device
	// number), giving slots 0..31
	pciSlotBits = 5
	maxPciSlot  = (1 << pciSlotBits) - 1

	pcidomainBits = 16
	maxPcidomain  = (1 << pcidomainBits) - 1
)

// A PciSlot describes where a PCI device sits on a single bus
//
// This encapsulates the PCI slot number a.k.a device number, which is
// limited to a 5 bit value [0x00..0x1f] by the PCI specification
//
// XXX In order to support multifunction device's we'll need to extend
// this to include the PCI 3-bit function number as well.
type PciSlot struct {
	domain	uint16
	slot    uint8
}

func PciSlotFromString(s string) (PciSlot, error) {
	tokens := strings.Split(s, ":")
	if len(tokens) == 3 {
		return PciSlotFromBdfString(tokens)
	} else {
		device, err := PciSlotFromDeviceIndexString(s)
		if err != nil {
			return PciSlot{}, err
		}

		return PciSlot{domain: 0, slot: uint8(device)}, nil
	}
}

func PciSlotFromDeviceIndexString(s string) (uint64, error) {
	return strconv.ParseUint(s, 16, pciSlotBits)
}

func PciSlotFromBdfString(bdfTokens []string) (PciSlot, error) {
	if bdfTokens[1] != "00" {
		return PciSlot{}, fmt.Errorf("Unexpected PCI bus index %q", bdfTokens[1])
	}

	domain, err := strconv.ParseUint(bdfTokens[0], 16, pcidomainBits)
	if err != nil {
		return PciSlot{}, err
	}

	deviceTokens := strings.Split(bdfTokens[2], ".")
	if len(deviceTokens) != 2 || deviceTokens[1] != "0" || len(deviceTokens[0]) != 2 {
		return PciSlot{}, fmt.Errorf("Unexpected PCI BDF device format %q", bdfTokens[2])
	}

	device, err := PciSlotFromDeviceIndexString(deviceTokens[0])
	if err != nil {
		return PciSlot{}, err
	}

	return PciSlot{domain: uint16(domain), slot: uint8(device)}, nil
}

func PciSlotFromInt(v int) (PciSlot, error) {
	if v < 0 || v > maxPciSlot {
		return PciSlot{}, fmt.Errorf("PCI slot 0x%x should be in range [0..0x%x]", v, maxPciSlot)
	}
	return PciSlot{domain: 0, slot: uint8(v)}, nil
}

func (slot PciSlot) String() string {
	if slot.domain == 0 {
		return fmt.Sprintf("%02x", slot.slot)
	} else {
		return fmt.Sprintf("%04x:00:%02x.0", slot.domain, slot.slot)
	}
}

// A PciPath describes where a PCI sits in a PCI hierarchy.
//
// Consists of a list of PCI slots, giving the slot of each bridge
// that must be traversed from the PCI root to reach the device,
// followed by the slot of the device itself
//
// When formatted into a string is written as "xx/.../yy/zz" Here, zz
// is the slot of the device on its PCI bridge, yy is the slot of the
// bridge on its parent bridge and so forth until xx is the slot of
// the "most upstream" bridge on the root bus.  If a device is
// connected directly to the root bus, its PciPath is just "zz"
type PciPath struct {
	slots []PciSlot
}

func (p PciPath) String() string {
	tokens := make([]string, len(p.slots))
	for i, slot := range p.slots {
		tokens[i] = slot.String()
	}
	return strings.Join(tokens, "/")
}

func (p PciPath) IsNil() bool {
	return p.slots == nil
}

func (p PciPath) ToArray() []uint32 {
	var slots []uint32
	for _, slot := range p.slots {
		slots = append(slots, uint32(slot.slot))
	}
	return slots
}

func PciPathFromString(s string) (PciPath, error) {
	if s == "" {
		return PciPath{}, nil
	}

	tokens := strings.Split(s, "/")
	slots := make([]PciSlot, len(tokens))
	for i, t := range tokens {
		var err error
		slots[i], err = PciSlotFromString(t)
		if err != nil {
			return PciPath{}, err
		}
	}
	return PciPath{slots: slots}, nil
}

func PciPathFromSlots(slots ...PciSlot) (PciPath, error) {
	if len(slots) == 0 {
		return PciPath{}, fmt.Errorf("PCI path needs at least one component")
	}
	return PciPath{slots: slots}, nil
}
