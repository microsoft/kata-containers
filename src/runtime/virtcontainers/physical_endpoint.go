//go:build linux

// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package virtcontainers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/config"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/drivers"
	resCtrl "github.com/kata-containers/kata-containers/src/runtime/pkg/resourcecontrol"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	vcTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/safchain/ethtool"
	logrus "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var physicalTrace = getNetworkTrace(PhysicalEndpointType)

// PhysicalEndpoint gathers a physical network interface and its properties
type PhysicalEndpoint struct {
	IfaceName          string
	IsVFIO             bool
	HardAddr           string
	EndpointProperties NetworkInfo
	EndpointType       EndpointType
	BDF                string
	Driver             string
	VendorDeviceID     string
	PCIPath            vcTypes.PciPath
	CCWDevice          *vcTypes.CcwDevice
	NetPair            NetworkInterfacePair
	BusType            string
	RxRateLimiter      bool
	TxRateLimiter      bool
}

// Properties returns the properties of the physical interface.
func (endpoint *PhysicalEndpoint) Properties() NetworkInfo {
	return endpoint.EndpointProperties
}

// HardwareAddr returns the mac address of the physical network interface.
func (endpoint *PhysicalEndpoint) HardwareAddr() string {
	return endpoint.HardAddr
}

// Name returns name of the physical interface.
func (endpoint *PhysicalEndpoint) Name() string {
	return endpoint.IfaceName
}

// Type indentifies the endpoint as a physical endpoint.
func (endpoint *PhysicalEndpoint) Type() EndpointType {
	return endpoint.EndpointType
}

// PciPath returns the PCI path of the endpoint.
func (endpoint *PhysicalEndpoint) PciPath() vcTypes.PciPath {
	return endpoint.PCIPath
}

// SetPciPath sets the PCI path of the endpoint.
func (endpoint *PhysicalEndpoint) SetPciPath(pciPath vcTypes.PciPath) {
	endpoint.PCIPath = pciPath
}

// CcwDevice returns the CCW device of the endpoint.
func (endpoint *PhysicalEndpoint) CcwDevice() *vcTypes.CcwDevice {
	return endpoint.CCWDevice
}

// SetCcwDevice sets the CCW device of the endpoint.
func (endpoint *PhysicalEndpoint) SetCcwDevice(ccwDev vcTypes.CcwDevice) {
	endpoint.CCWDevice = &ccwDev
}

// SetProperties sets the properties of the physical endpoint.
func (endpoint *PhysicalEndpoint) SetProperties(properties NetworkInfo) {
	endpoint.EndpointProperties = properties
}

// NetworkPair returns the network pair of the endpoint.
func (endpoint *PhysicalEndpoint) NetworkPair() *NetworkInterfacePair {
	return &endpoint.NetPair
}

// Attach for physical endpoint binds the physical network interface to
// vfio-pci and adds device to the hypervisor with vfio-passthrough.
func (endpoint *PhysicalEndpoint) Attach(ctx context.Context, s *Sandbox) error {
	span, ctx := physicalTrace(ctx, "Attach", endpoint)
	defer span.End()
	if endpoint.IsVFIO {
		// Unbind physical interface from host driver and bind to vfio
		// so that it can be passed to qemu.
		vfioPath, err := bindNICToVFIO(endpoint)
		if err != nil {
			return err
		}
		c, err := resCtrl.DeviceToCgroupDeviceRule(vfioPath)
		if err != nil {
			return err
		}
		d := config.DeviceInfo{
			ContainerPath: vfioPath,
			DevType:       string(c.Type),
			Major:         c.Major,
			Minor:         c.Minor,
			ColdPlug:      true,
			Port:          s.config.HypervisorConfig.ColdPlugVFIO,
		}
		_, err = s.AddDevice(ctx, d)
		return err
	} else {
		h := s.hypervisor
		if err := xConnectVMNetwork(ctx, endpoint, h); err != nil {
			networkLogger().WithError(err).Error("Error bridging physical endpoint")
			return err
		}
		if err := h.AddDevice(ctx, endpoint, NetDev); err != nil {
			networkLogger().WithError(err).Error("Error adding physical endpoint device")
			return err
		}
		return nil
	}
}

// Detach for physical endpoint unbinds the physical network interface from vfio-pci
// and binds it back to the saved host driver.
func (endpoint *PhysicalEndpoint) Detach(ctx context.Context, netNsCreated bool, netNsPath string) error {
	span, _ := physicalTrace(ctx, "Detach", endpoint)
	defer span.End()
	if endpoint.IsVFIO {
		// Bind back the physical network interface to host.
		// We need to do this even if a new network namespace has not
		// been created by virtcontainers.
		// We do not need to enter the network namespace to bind back the
		// physical interface to host driver.
		return bindNICToHost(endpoint)
	} else {
		// The network namespace would have been deleted at this point
		// if it has not been created by virtcontainers.
		if !netNsCreated {
			return nil
		}
		return doNetNS(netNsPath, func(_ ns.NetNS) error {
			return xDisconnectVMNetwork(ctx, endpoint)
		})
	}
}

// HotAttach for physical endpoint not supported yet
func (endpoint *PhysicalEndpoint) HotAttach(ctx context.Context, s *Sandbox) error {
	span, ctx := physicalTrace(ctx, "HotAttach", endpoint)
	defer span.End()
	if endpoint.IsVFIO {
		// Unbind physical interface from host driver and bind to vfio
		// so that it can be passed to the hypervisor.
		vfioPath, err := bindNICToVFIO(endpoint)
		if err != nil {
			return err
		}
		c, err := resCtrl.DeviceToCgroupDeviceRule(vfioPath)
		if err != nil {
			return err
		}
		d := config.DeviceInfo{
			ContainerPath: vfioPath,
			DevType:       string(c.Type),
			Major:         c.Major,
			Minor:         c.Minor,
			ColdPlug:      false,
		}
		_, err = s.AddDevice(ctx, d)
		return err
	} else {
		h := s.hypervisor
		if err := xConnectVMNetwork(ctx, endpoint, h); err != nil {
			networkLogger().WithError(err).Error("Error bridging physical endpoint (hotplug)")
			return err
		}
		if _, err := h.HotplugAddDevice(ctx, endpoint, NetDev); err != nil {
			networkLogger().WithError(err).Error("Error hotplugging physical endpoint device")
			return err
		}
		return nil
	}
}

// HotDetach for physical endpoint not supported yet
func (endpoint *PhysicalEndpoint) HotDetach(ctx context.Context, s *Sandbox, netNsCreated bool, netNsPath string) error {
	span, _ := physicalTrace(ctx, "HotDetach", endpoint)
	defer span.End()
	var vfioPath string
	var err error
	if endpoint.IsVFIO {
		if vfioPath, err = drivers.GetVFIODevPath(endpoint.BDF); err != nil {
			return err
		}
		c, err := resCtrl.DeviceToCgroupDeviceRule(vfioPath)
		if err != nil {
			return err
		}
		d := config.DeviceInfo{
			ContainerPath: vfioPath,
			DevType:       string(c.Type),
			Major:         c.Major,
			Minor:         c.Minor,
			ColdPlug:      false,
		}
		device := s.devManager.FindDevice(&d)
		s.devManager.RemoveDevice(device.DeviceID())
		// We do not need to enter the network namespace to bind back the
		// physical interface to host driver.
		return bindNICToHost(endpoint)
	} else {
		if !netNsCreated {
			return nil
		}
		span, ctx := vethTrace(ctx, "HotDetach", endpoint)
		defer span.End()
		if err := doNetNS(netNsPath, func(_ ns.NetNS) error {
			return xDisconnectVMNetwork(ctx, endpoint)
		}); err != nil {
			networkLogger().WithError(err).Warn("Error un-bridging virtual ep")
		}
		h := s.hypervisor
		if _, err := h.HotplugRemoveDevice(ctx, endpoint, NetDev); err != nil {
			return err
		}
		return nil
	}
}

// isPhysicalIface checks if an interface is a physical device by inspecting
// the link's ParentDevBus attribute. Returns true when the bus is "pci" or
// "vmbus". ParentDevBus is populated by the kernel via netlink
// and does not require sysfs access inside the network namespace.
func isPhysicalIface(link netlink.Link) bool {
	isParent := (link.Attrs().ParentDevBus == "pci" || link.Attrs().ParentDevBus == "vmbus")
	return isParent
}

var sysBusPath = "/sys/bus/"

// findSubordinateVF looks for a PCI virtual function (VF) paired with a
// VMBus netvsc NIC. On Azure with Accelerated Networking, the hv_netvsc
// driver bonds a Mellanox (or other) SR-IOV VF as a lower device for
// data-plane acceleration.
//
// The kata shim enters the pod's network namespace via setns(CLONE_NEWNET)
// but does NOT remount sysfs, so /sys/class/net/ still reflects the host's
// view.  Netlink and ethtool operate on the current network namespace
// regardless of mount namespace, so we use those instead for discovery.
//
// Returns the VF's PCI BDF (e.g. "8cd5:00:02.0") when found, or an
// empty string when no subordinate VF exists.
func findSubordinateVF(ifaceName string) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("listing links to find subordinate VF: %w", err)
	}

	networkLogger().WithFields(logrus.Fields{
		"iface":      ifaceName,
		"link-count": len(links),
	}).Info("findSubordinateVF: enumerating netns links for PCI VF")

	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return "", fmt.Errorf("creating ethtool handle for VF discovery: %w", err)
	}
	defer ethHandle.Close()

	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == ifaceName {
			continue
		}
		if attrs.ParentDevBus != "pci" {
			networkLogger().WithFields(logrus.Fields{
				"link":           attrs.Name,
				"parent-dev-bus": attrs.ParentDevBus,
			}).Debug("findSubordinateVF: skipping non-PCI link")
			continue
		}

		bdf, err := ethHandle.BusInfo(attrs.Name)
		if err != nil {
			networkLogger().WithError(err).WithField("link", attrs.Name).Debug("findSubordinateVF: skipping PCI link, ethtool BusInfo failed")
			continue
		}

		networkLogger().WithFields(logrus.Fields{
			"parent-iface":       ifaceName,
			"subordinate-iface":  attrs.Name,
			"subordinate-hwaddr": attrs.HardwareAddr,
			"vf-bdf":             bdf,
		}).Info("Discovered subordinate PCI VF via netlink")

		return bdf, nil
	}

	networkLogger().WithField("iface", ifaceName).Info("findSubordinateVF: no subordinate PCI VF found in netns")
	return "", nil
}

// Get vendor and device id from pci space (sys/bus/pci/devices, or sys/bus/vmbus/devices, ...)
func getDevicesPath(link netlink.Link) string {
	return filepath.Join(sysBusPath, link.Attrs().ParentDevBus, "devices")
}

// Get vendor and device id from pci space (sys/bus/pci/devices/$BusDeviceInfo)
func getIfaceDevicePath(link netlink.Link, deviceInterfaceName string) (string, string, error) {
	if link.Attrs().ParentDevBus == "pci" {
		// Get ethtool handle to derive driver and bus
		ethHandle, err := ethtool.NewEthtool()
		if err != nil {
			return "", "", err
		}
		defer ethHandle.Close()
		// Get Bus info
		bdf, err := ethHandle.BusInfo(deviceInterfaceName)
		if err != nil {
			return "", "", err
		}
		// Get device by following symlink /sys/bus/pci/devices/$bdf
		return filepath.Join(getDevicesPath(link), bdf), bdf, nil
	} else if link.Attrs().ParentDevBus == "vmbus" {
		return filepath.Join(getDevicesPath(link), link.Attrs().ParentDev), link.Attrs().ParentDev, nil
	} else {
		return "", "", fmt.Errorf("unsupported ParentDevBus: %s", link.Attrs().ParentDevBus)
	}
}
func createPhysicalEndpoint(idx int, netInfo NetworkInfo, isFVIODisabled bool, interworkingModel NetInterworkingModel) (*PhysicalEndpoint, error) {
	attrs := netInfo.Link.Attrs()
	networkLogger().WithFields(logrus.Fields{
		"iface-name":     netInfo.Iface.Name,
		"iface-index":    netInfo.Iface.Index,
		"iface-mtu":      netInfo.Iface.MTU,
		"iface-hwaddr":   netInfo.Iface.HardwareAddr,
		"iface-flags":    netInfo.Iface.Flags,
		"link-type":      netInfo.Link.Type(),
		"link-name":      attrs.Name,
		"link-index":     attrs.Index,
		"link-mtu":       attrs.MTU,
		"link-hwaddr":    attrs.HardwareAddr,
		"link-encap":     attrs.EncapType,
		"link-operstate": attrs.OperState,
		"parent-dev":     attrs.ParentDev,
		"parent-dev-bus": attrs.ParentDevBus,
		"parent-index":   attrs.ParentIndex,
		"master-index":   attrs.MasterIndex,
		"alias":          attrs.Alias,
		"num-addrs":      len(netInfo.Addrs),
		"num-routes":     len(netInfo.Routes),
	}).Info("createPhysicalEndpoint: netInfo details for device correlation")

	sysIfaceDevicePath, bdf, err := getIfaceDevicePath(netInfo.Link, netInfo.Iface.Name)
	if err != nil {
		return nil, err
	}

	// For VMBus devices, attempt to discover a subordinate PCI VF
	// (e.g. mlx5 VF under netvsc with Azure Accelerated Networking).
	// When found, use VFIO passthrough on the VF instead of virtio-net.
	// When no subordinate VF is present, fall through to the virtio-net
	// network pair path.
	busType := netInfo.Link.Attrs().ParentDevBus
	isVFIO := (busType == "pci")
	if busType == "vmbus" {
		vfBDF, vfErr := findSubordinateVF(netInfo.Iface.Name)
		if vfErr != nil {
			networkLogger().WithError(vfErr).Warn("Error searching for subordinate VF, falling back to virtio-net pair")
		} else if vfBDF != "" {
			networkLogger().WithFields(logrus.Fields{
				"vmbus-guid": bdf,
				"vf-bdf":     vfBDF,
				"iface":      netInfo.Iface.Name,
			}).Info("Using subordinate PCI VF for VFIO passthrough instead of virtio-net pair")
			sysIfaceDevicePath = filepath.Join(sysBusPath, "pci", "devices", vfBDF)
			bdf = vfBDF
			busType = "pci"
			isVFIO = true
		}
	}

	// Get driver by following symlink /sys/bus/pci/devices/$bdf/driver or /sys/bus/vmbus/devices/$guid/driver
	driverPath := filepath.Join(sysIfaceDevicePath, "driver")
	link, err := os.Readlink(driverPath)
	if err != nil {
		return nil, err
	}
	driver := filepath.Base(link)
	// Get device by following symlink /sys/bus/pci/devices/$bdf/device or /sys/bus/vmbus/devices/$guid/device
	ifaceDevicePath := filepath.Join(sysIfaceDevicePath, "device")
	contents, err := os.ReadFile(ifaceDevicePath)
	if err != nil {
		return nil, err
	}
	deviceID := strings.TrimSpace(string(contents))
	// Vendor id (/sys/bus/pci/devices/$bdf/device or /sys/bus/vmbus/devices/$guid/driver)
	ifaceVendorPath := filepath.Join(sysIfaceDevicePath, "vendor")
	contents, err = os.ReadFile(ifaceVendorPath)
	if err != nil {
		return nil, err
	}
	netPair := NetworkInterfacePair{}
	if isVFIO {
		if isFVIODisabled {
			// When `cold_plug_vfio` is set to "no-port", the PhysicalEndpoint's VFIO device cannot be attached to the guest VM.
			// Fail early to prevent the interface from being unbound and rebound to the VFIO driver.
			return nil, fmt.Errorf("Unable to add PhysicalEndpoint %s because cold_plug_vfio is disabled", netInfo.Iface.Name)
		}
	} else {
		if idx < 0 {
			return nil, fmt.Errorf("invalid network endpoint index: %d", idx)
		}
		netPair, err = createNetworkInterfacePair(idx, netInfo.Iface.Name, interworkingModel)
		if err != nil {
			return nil, err
		}
		if netInfo.Iface.Name != "" {
			netPair.VirtIface.Name = netInfo.Iface.Name
		}
	}
	vendorID := strings.TrimSpace(string(contents))
	vendorDeviceID := fmt.Sprintf("%s %s", vendorID, deviceID)
	vendorDeviceID = strings.TrimSpace(vendorDeviceID)
	physicalEndpoint := &PhysicalEndpoint{
		IfaceName:      netInfo.Iface.Name,
		IsVFIO:         isVFIO,
		HardAddr:       netInfo.Iface.HardwareAddr.String(),
		VendorDeviceID: vendorDeviceID,
		EndpointType:   PhysicalEndpointType,
		Driver:         driver,
		BDF:            bdf,
		NetPair:        netPair,
		BusType:        busType,
	}
	return physicalEndpoint, nil
}
func bindNICToVFIO(endpoint *PhysicalEndpoint) (string, error) {
	return drivers.BindDevicetoVFIO(endpoint.BDF, endpoint.Driver)
}
func bindNICToHost(endpoint *PhysicalEndpoint) error {
	return drivers.BindDevicetoHost(endpoint.BDF, endpoint.Driver)
}
func (endpoint *PhysicalEndpoint) save() persistapi.NetworkEndpoint {
	netpair := saveNetIfPair(&endpoint.NetPair)
	return persistapi.NetworkEndpoint{
		Type: string(endpoint.Type()),
		Physical: &persistapi.PhysicalEndpoint{
			BDF:            endpoint.BDF,
			Driver:         endpoint.Driver,
			VendorDeviceID: endpoint.VendorDeviceID,
			NetPair:        *netpair,
			BusType:        endpoint.BusType,
			IsVFIO:         endpoint.IsVFIO,
		},
	}
}
func (endpoint *PhysicalEndpoint) load(s persistapi.NetworkEndpoint) {
	endpoint.EndpointType = PhysicalEndpointType
	if s.Physical != nil {
		netpair := loadNetIfPair(&s.Physical.NetPair)
		endpoint.NetPair = *netpair
		endpoint.BDF = s.Physical.BDF
		endpoint.Driver = s.Physical.Driver
		endpoint.VendorDeviceID = s.Physical.VendorDeviceID
		endpoint.BusType = s.Physical.BusType
		endpoint.IsVFIO = s.Physical.IsVFIO
	}
}

func (endpoint *PhysicalEndpoint) GetRxRateLimiter() bool {
	return endpoint.RxRateLimiter
}
func (endpoint *PhysicalEndpoint) SetRxRateLimiter() error {
	endpoint.RxRateLimiter = true
	return nil
}

func (endpoint *PhysicalEndpoint) GetTxRateLimiter() bool {
	return endpoint.TxRateLimiter
}
func (endpoint *PhysicalEndpoint) SetTxRateLimiter() error {
	endpoint.TxRateLimiter = true
	return nil
}
