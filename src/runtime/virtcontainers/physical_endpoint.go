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
			return err
		}
		return h.AddDevice(ctx, endpoint, NetDev)
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
			return err
		}
		if _, err := h.HotplugAddDevice(ctx, endpoint, NetDev); err != nil {
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

// isPhysicalIface checks if an interface is a physical device by reading
// the device's bus subsystem via sysfs. Returns true when the bus is "pci"
// or "vmbus", along with the bus type string.
func isPhysicalIface(ifaceName string) (bool, string) {
	if ifaceName == "lo" {
		return false, ""
	}
	busType, err := getIfaceBusType(ifaceName)
	if err != nil {
		return false, ""
	}
	if busType == "pci" || busType == "vmbus" {
		return true, busType
	}
	return false, ""
}

var sysClassNetPath = "/sys/class/net"

// getIfaceBusType returns the bus type (e.g. "pci", "vmbus") for a network
// interface by resolving the /sys/class/net/<ifname>/device/subsystem symlink.
func getIfaceBusType(ifaceName string) (string, error) {
	subsystem, err := os.Readlink(filepath.Join(sysClassNetPath, ifaceName, "device", "subsystem"))
	if err != nil {
		return "", err
	}
	return filepath.Base(subsystem), nil
}

// getIfaceDeviceOnBus returns the device identifier on the bus for the given
// interface by reading the basename of the /sys/class/net/<ifname>/device symlink.
func getIfaceDeviceOnBus(ifaceName string) (string, error) {
	device, err := os.Readlink(filepath.Join(sysClassNetPath, ifaceName, "device"))
	if err != nil {
		return "", err
	}
	return filepath.Base(device), nil
}

var sysBusPath = "/sys/bus/"

// getDevicesPath returns the sysfs devices directory for the given bus type.
func getDevicesPath(busType string) string {
	return filepath.Join(sysBusPath, busType, "devices")
}

// getIfaceDevicePath returns the sysfs device path and bus device identifier
// for a network interface.
func getIfaceDevicePath(busType string, ifaceName string) (string, string, error) {
	if busType == "pci" {
		// Get ethtool handle to derive driver and bus
		ethHandle, err := ethtool.NewEthtool()
		if err != nil {
			return "", "", err
		}
		defer ethHandle.Close()
		// Get Bus info
		bdf, err := ethHandle.BusInfo(ifaceName)
		if err != nil {
			return "", "", err
		}
		return filepath.Join(getDevicesPath(busType), bdf), bdf, nil
	} else if busType == "vmbus" {
		deviceID, err := getIfaceDeviceOnBus(ifaceName)
		if err != nil {
			return "", "", err
		}
		return filepath.Join(getDevicesPath(busType), deviceID), deviceID, nil
	} else {
		return "", "", fmt.Errorf("unsupported bus type: %s", busType)
	}
}
func createPhysicalEndpoint(idx int, netInfo NetworkInfo, busType string, isFVIODisabled bool, interworkingModel NetInterworkingModel) (*PhysicalEndpoint, error) {
	sysIfaceDevicePath, bdf, err := getIfaceDevicePath(busType, netInfo.Iface.Name)
	if err != nil {
		return nil, err
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
	// Determine whether to use VFIO passthrough based on bus type:
	// PCI devices are passed through via VFIO.
	// VMBus devices use a network pair (tap/bridge).
	isVFIO := (busType == "pci")
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
