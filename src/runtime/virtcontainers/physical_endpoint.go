//go:build linux

// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

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
	"github.com/vishvananda/netlink"
)

var physicalTrace = getNetworkTrace(PhysicalEndpointType)

// PhysicalEndpoint gathers a physical network interface and its properties
type PhysicalEndpoint struct {
	IfaceName          string
	IsVF               bool
	HardAddr           string
	EndpointProperties NetworkInfo
	EndpointType       EndpointType
	BDF                string
	Driver             string
	VendorDeviceID     string
	PCIPath            vcTypes.PciPath
	CCWDevice          *vcTypes.CcwDevice
	NetPair            NetworkInterfacePair
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

	if endpoint.IsVF {
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

	if endpoint.IsVF {

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

	if endpoint.IsVF {
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

	if endpoint.IsVF {
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

// isPhysicalIface checks if an interface is a physical device.
// We use ethtool here to not rely on device sysfs inside the network namespace.
func isPhysicalIface(link netlink.Link) bool {

	isParent := (link.Attrs().ParentDevBus == "pci" || link.Attrs().ParentDevBus == "vmbus")
	return isParent
	//return false
}

var sysBusPath = "/sys/bus/"

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

	sysIfaceDevicePath, bdf, err := getIfaceDevicePath(netInfo.Link, netInfo.Iface.Name)
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

	// A common way to identify VFs is by checking for the 'physfn' symlink
	// pointing to the Physical Function (PF)
	isVF := true
	netPair := NetworkInterfacePair{}
	_, err = filepath.EvalSymlinks(filepath.Join(ifaceDevicePath, "physfn"))
	if err != nil {
		isVF = false

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
	} else {
		if isFVIODisabled {
			// When `cold_plug_vfio` is set to "no-port", the PhysicalEndpoint's VFIO device cannot be attached to the guest VM.
			// Fail early to prevent the VF interface from being unbound and rebound to the VFIO driver.
			return nil, fmt.Errorf("Unable to add PhysicalEndpoint %s because cold_plug_vfio is disabled", netInfo.Iface.Name)
		}
	}

	vendorID := strings.TrimSpace(string(contents))
	vendorDeviceID := fmt.Sprintf("%s %s", vendorID, deviceID)
	vendorDeviceID = strings.TrimSpace(vendorDeviceID)

	physicalEndpoint := &PhysicalEndpoint{
		IfaceName:      netInfo.Iface.Name,
		IsVF:           isVF,
		HardAddr:       netInfo.Iface.HardwareAddr.String(),
		VendorDeviceID: vendorDeviceID,
		EndpointType:   PhysicalEndpointType,
		Driver:         driver,
		BDF:            bdf,
		NetPair:        netPair,
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
		},
	}
}

func (endpoint *PhysicalEndpoint) load(s persistapi.NetworkEndpoint) {
	endpoint.EndpointType = PhysicalEndpointType

	if s.Physical != nil {
		netpair := loadNetIfPair(&s.Veth.NetPair)
		endpoint.NetPair = *netpair
		endpoint.BDF = s.Physical.BDF
		endpoint.Driver = s.Physical.Driver
		endpoint.VendorDeviceID = s.Physical.VendorDeviceID
	}
}

// unsupported
func (endpoint *PhysicalEndpoint) GetRxRateLimiter() bool {
	return false
}

func (endpoint *PhysicalEndpoint) SetRxRateLimiter() error {
	return fmt.Errorf("rx rate limiter is unsupported for physical endpoint")
}

// unsupported
func (endpoint *PhysicalEndpoint) GetTxRateLimiter() bool {
	return false
}

func (endpoint *PhysicalEndpoint) SetTxRateLimiter() error {
	return fmt.Errorf("tx rate limiter is unsupported for physical endpoint")
}
