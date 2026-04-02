//go:build linux

// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	ktu "github.com/kata-containers/kata-containers/src/runtime/pkg/katatestutils"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestPhysicalEndpoint_HotAttach_VF(t *testing.T) {
	assert := assert.New(t)
	v := &PhysicalEndpoint{
		IfaceName: "eth0",
		HardAddr:  net.HardwareAddr{0x02, 0x00, 0xca, 0xfe, 0x00, 0x04}.String(),
		IsVF:      true,
	}

	s := &Sandbox{
		hypervisor: &mockHypervisor{},
	}

	// VF path tries to bind to VFIO which fails without real hardware
	err := v.HotAttach(context.Background(), s)
	assert.Error(err)
}

func TestPhysicalEndpoint_HotAttach_NonVF(t *testing.T) {
	assert := assert.New(t)
	v := &PhysicalEndpoint{
		IfaceName: "eth0",
		HardAddr:  net.HardwareAddr{0x02, 0x00, 0xca, 0xfe, 0x00, 0x04}.String(),
		IsVF:      false,
	}

	s := &Sandbox{
		hypervisor: &mockHypervisor{},
	}

	// Non-VF path tries xConnectVMNetwork which fails without tap/bridge setup
	err := v.HotAttach(context.Background(), s)
	assert.Error(err)
}

func TestPhysicalEndpoint_HotDetach_VF(t *testing.T) {
	assert := assert.New(t)
	v := &PhysicalEndpoint{
		IfaceName: "eth0",
		HardAddr:  net.HardwareAddr{0x02, 0x00, 0xca, 0xfe, 0x00, 0x04}.String(),
		IsVF:      true,
	}

	s := &Sandbox{
		hypervisor: &mockHypervisor{},
	}

	// VF path tries to get VFIO dev path which fails without real hardware
	err := v.HotDetach(context.Background(), s, true, "")
	assert.Error(err)
}

func TestPhysicalEndpoint_HotDetach_NonVF_NetNsNotCreated(t *testing.T) {
	assert := assert.New(t)
	v := &PhysicalEndpoint{
		IfaceName: "eth0",
		HardAddr:  net.HardwareAddr{0x02, 0x00, 0xca, 0xfe, 0x00, 0x04}.String(),
		IsVF:      false,
	}

	s := &Sandbox{
		hypervisor: &mockHypervisor{},
	}

	// Non-VF with netNsCreated=false should return nil immediately
	err := v.HotDetach(context.Background(), s, false, "")
	assert.NoError(err)
}

func TestPhysicalEndpoint_HotDetach_NonVF_NetNsCreated(t *testing.T) {
	assert := assert.New(t)
	v := &PhysicalEndpoint{
		IfaceName: "eth0",
		HardAddr:  net.HardwareAddr{0x02, 0x00, 0xca, 0xfe, 0x00, 0x04}.String(),
		IsVF:      false,
	}

	s := &Sandbox{
		hypervisor: &mockHypervisor{},
	}

	// Non-VF with netNsCreated=true but empty path calls doNetNS("", ...),
	// xDisconnectVMNetwork error is only logged as a warning (not returned).
	// mockHypervisor.HotplugRemoveDevice succeeds, so overall returns nil.
	err := v.HotDetach(context.Background(), s, true, "")
	assert.NoError(err)
}

func TestPhysicalEndpoint_NetworkPair(t *testing.T) {
	assert := assert.New(t)

	netPair := NetworkInterfacePair{
		VirtIface: NetworkInterface{
			Name: "eth0",
		},
	}

	v := &PhysicalEndpoint{
		IfaceName: "eth0",
		NetPair:   netPair,
	}

	result := v.NetworkPair()
	assert.NotNil(result)
	assert.Equal("eth0", result.VirtIface.Name)
}

func TestPhysicalEndpoint_Detach_NonVF_NetNsNotCreated(t *testing.T) {
	assert := assert.New(t)
	v := &PhysicalEndpoint{
		IfaceName: "eth0",
		HardAddr:  net.HardwareAddr{0x02, 0x00, 0xca, 0xfe, 0x00, 0x04}.String(),
		IsVF:      false,
	}

	// Non-VF with netNsCreated=false should return nil immediately
	err := v.Detach(context.Background(), false, "")
	assert.NoError(err)
}

func TestIsPhysicalIface(t *testing.T) {
	assert := assert.New(t)

	if tc.NotValid(ktu.NeedRoot()) {
		t.Skip(testDisabledAsNonRoot)
	}

	testNetIface := "testIface0"
	testMTU := 1500
	testMACAddr := "00:00:00:00:00:01"

	hwAddr, err := net.ParseMAC(testMACAddr)
	assert.NoError(err)

	link := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         testNetIface,
			MTU:          testMTU,
			HardwareAddr: hwAddr,
			TxQLen:       -1,
			ParentDevBus: "pci",
		},
	}

	n, err := testutils.NewNS()
	assert.NoError(err)
	defer n.Close()

	netnsHandle, err := netns.GetFromPath(n.Path())
	assert.NoError(err)
	defer netnsHandle.Close()

	netlinkHandle, err := netlink.NewHandleAt(netnsHandle)
	assert.NoError(err)
	defer netlinkHandle.Close()

	err = netlinkHandle.LinkAdd(link)
	assert.NoError(err)

	var isPhysical bool
	err = doNetNS(n.Path(), func(_ ns.NetNS) error {
		isPhysical = isPhysicalIface(link)
		return nil
	})
	assert.NoError(err)
	assert.False(isPhysical)
}

func TestIsPhysicalIface_PCI(t *testing.T) {
	assert := assert.New(t)
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "eth0",
			ParentDevBus: "pci",
		},
	}
	assert.True(isPhysicalIface(link))
}

func TestIsPhysicalIface_VMBus(t *testing.T) {
	assert := assert.New(t)
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "eth0",
			ParentDevBus: "vmbus",
		},
	}
	assert.True(isPhysicalIface(link))
}

func TestIsPhysicalIface_NoBus(t *testing.T) {
	assert := assert.New(t)
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "veth0",
			ParentDevBus: "",
		},
	}
	assert.False(isPhysicalIface(link))
}

func TestGetDevicesPath(t *testing.T) {
	assert := assert.New(t)

	pciLink := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			ParentDevBus: "pci",
		},
	}
	assert.Equal("/sys/bus/pci/devices", getDevicesPath(pciLink))

	vmbusLink := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			ParentDevBus: "vmbus",
		},
	}
	assert.Equal("/sys/bus/vmbus/devices", getDevicesPath(vmbusLink))
}

func TestGetIfaceDevicePath_UnsupportedBus(t *testing.T) {
	assert := assert.New(t)

	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			ParentDevBus: "usb",
		},
	}
	_, _, err := getIfaceDevicePath(link, "eth0")
	assert.Error(err)
	assert.Contains(err.Error(), "unsupported ParentDevBus")
}

func TestGetIfaceDevicePath_VMBus(t *testing.T) {
	assert := assert.New(t)

	guid := "00000000-0000-0000-0000-000000000001"
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			ParentDevBus: "vmbus",
			ParentDev:    guid,
		},
	}
	path, bdf, err := getIfaceDevicePath(link, "eth0")
	assert.NoError(err)
	assert.Equal(guid, bdf)
	assert.Equal(filepath.Join("/sys/bus/vmbus/devices", guid), path)
}

func TestCreatePhysicalEndpoint_NegativeIdx(t *testing.T) {
	assert := assert.New(t)

	// Create a temp directory to mock sysfs
	tmpDir := t.TempDir()
	origSysBusPath := sysBusPath
	sysBusPath = tmpDir
	defer func() { sysBusPath = origSysBusPath }()

	guid := "00000000-0000-0000-0000-000000000001"
	vmbusDevDir := filepath.Join(tmpDir, "vmbus", "devices", guid)
	assert.NoError(os.MkdirAll(vmbusDevDir, 0755))

	// Create driver symlink
	driverTarget := filepath.Join(tmpDir, "drivers", "hv_netvsc")
	assert.NoError(os.MkdirAll(driverTarget, 0755))
	assert.NoError(os.Symlink(driverTarget, filepath.Join(vmbusDevDir, "driver")))

	// Create device and vendor files
	assert.NoError(os.WriteFile(filepath.Join(vmbusDevDir, "device"), []byte("0x1572\n"), 0644))
	assert.NoError(os.WriteFile(filepath.Join(vmbusDevDir, "vendor"), []byte("0x8086\n"), 0644))

	// No physfn symlink → not a VF → negative idx should fail
	hwAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	netInfo := NetworkInfo{
		Iface: NetlinkIface{
			LinkAttrs: netlink.LinkAttrs{
				Name:         "eth0",
				ParentDevBus: "vmbus",
				ParentDev:    guid,
				HardwareAddr: hwAddr,
			},
			Type: "",
		},
		Link: &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:         "eth0",
				ParentDevBus: "vmbus",
				ParentDev:    guid,
				HardwareAddr: hwAddr,
			},
		},
	}

	_, err := createPhysicalEndpoint(-1, netInfo, false, DefaultNetInterworkingModel)
	assert.Error(err)
	assert.Contains(err.Error(), "invalid network endpoint index")
}
