package virtcontainers

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/containerd/console"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/config"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils/katatrace"
	openvmmservice "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/openvmm/protos"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// openvmmTracingTags defines tags for the trace span
var openvmmTracingTags = map[string]string{
	"source":    "runtime",
	"package":   "virtcontainers",
	"subsystem": "hypervisor",
	"type":      "openvmm",
}

//
// Constants and type definitions related to openvmm
//

type openvmmState uint8

const (
	openvmmNotReady openvmmState = iota
	openvmmReady
)

const (
	openvmmStateCreated = "Created"
	openvmmStateRunning = "Running"
)

const (
	openvmmGRPCTimeout = 2                   // Timeout for gRPC calls to OpenVMM in seconds
	openvmmVSocket     = "openvmm.sock"      // vsocket for OpenVMM
	openvmmAPISocket   = "openvmm-grpc.sock" // gRPC API socket for OpenVMM
	defaultOpenvmmPath = "/usr/local/bin/openvmm"
)

// OpenVMM hypervisor state
type OpenVMMHypervisorState struct {
	grpcSocket        string
	PID               int
	VirtiofsDaemonPid int
	apiSocket         string // gRPC API socket path
	state             openvmmState
}

// openvmm represents the OpenVMM hypervisor
type openvmm struct {
	console         console.Console
	virtiofsDaemon  VirtiofsDaemon
	grpcClient      openvmmservice.VMClient
	grpcConn        *grpc.ClientConn // Store connection for proper cleanup
	ctx             context.Context
	id              string
	netDevices      []*openvmmservice.NICConfig // Network devices for the VM (use slice of pointers)
	devicesIds      map[string]string
	netDevicesFiles map[string][]*os.File
	vmconfig        openvmmservice.VMConfig
	state           OpenVMMHypervisorState
	config          HypervisorConfig
	stopped         int32
	mu              sync.Mutex
}

var openvmmKernelParams = []Param{
	{"panic", "1"},         // upon kernel panic wait 1 second before reboot
	{"no_timer_check", ""}, // do not Check broken timer IRQ resources
	{"noreplace-smp", ""},  // do not replace SMP instructions
}

var openvmmDebugKernelParams = []Param{
	{"console", "ttyS0,115200n8"}, // enable serial console
}

var openvmmArmDebugKernelParams = []Param{
	{"console", "ttyAMA0,115200n8"}, // enable serial console
}

var openvmmDebugConfidentialGuestKernelParams = []Param{
	{"console", "hvc0"}, // enable HVC console
}

var openvmmDebugKernelParamsCommon = []Param{
	{"systemd.log_target", "console"}, // send loggng to the console
}

func (o *openvmm) setConfig(config *HypervisorConfig) error {
	o.config = *config

	return nil
}

func openvmmGetNonUserDefinedKernelParams(rootfstype string, disableNvdimm bool, dax bool, debug bool, confidential bool, iommu bool) ([]Param, error) {
	params, err := GetKernelRootParams(rootfstype, disableNvdimm, dax)
	if err != nil {
		return []Param{}, err
	}
	params = append(params, openvmmKernelParams...)

	if iommu {
		params = append(params, Param{"iommu", "pt"})
	}

	if !debug {
		// start the guest kernel with 'quiet' in non-debug mode
		params = append(params, Param{"quiet", ""})
		return params, nil
	}

	// In case of debug ...

	// Followed by extra debug parameters if debug enabled in configuration file
	if confidential {
		params = append(params, openvmmDebugConfidentialGuestKernelParams...)
	} else if runtime.GOARCH == "arm64" {
		params = append(params, openvmmArmDebugKernelParams...)
	} else {
		params = append(params, openvmmDebugKernelParams...)
	}
	params = append(params, openvmmDebugKernelParamsCommon...)
	return params, nil
}

//###########################################################################
//
// Public implementation of the Hypervisor interface
//
//###########################################################################

// For openvmm this call only sets the internal structure up.
// The VM will be created and started through ResumeVM().
func (o *openvmm) CreateVM(ctx context.Context, id string, network Network, hypervisorConfig *HypervisorConfig) error {
	o.ctx = ctx

	span, newCtx := katatrace.Trace(o.ctx, o.Logger(), "CreateVM", openvmmTracingTags, map[string]string{"sandbox_id": o.id})
	o.ctx = newCtx
	defer span.End()

	if err := o.setConfig(hypervisorConfig); err != nil {
		return err
	}

	o.id = id
	o.state.state = openvmmNotReady
	o.devicesIds = make(map[string]string)
	o.netDevicesFiles = make(map[string][]*os.File)

	o.Logger().WithField("function", "CreateVM").Info("creating Sandbox")

	if o.state.PID > 0 {
		o.Logger().WithField("function", "CreateVM").Info("Sandbox already exist, loading from state [NOT IMPLEMENTED]")
		return fmt.Errorf("OpenVMM restore not implemented")
	}

	// No need to return an error from there since there might be nothing
	// to fetch if this is the first time the hypervisor is created.
	o.Logger().WithField("function", "CreateVM").Info("Sandbox not found creating")

	// Create the VM config via the constructor to ensure default values are properly assigned
	o.vmconfig = *o.createDefaultVMConfig()

	// Make sure the kernel path is valid
	kernelPath, err := o.config.KernelAssetPath()
	if err != nil {
		return err
	}
	o.vmconfig.GetDirectBoot().KernelPath = kernelPath

	// Make sure the initrd path is valid
	initrdPath, err := o.config.InitrdAssetPath()
	if err != nil {
		return err
	}
	o.vmconfig.GetDirectBoot().InitrdPath = initrdPath

	if o.config.ConfidentialGuest {
		return fmt.Errorf("confidential guest mode is not supported by OpenVMM")
	}

	// Update the VM memory size as per the hypervisor config
	o.vmconfig.MemoryConfig.MemoryMb = uint64(utils.MemUnit(o.config.MemorySize).ToBytes())

	// TODO is there a Shared memory config needed here?
	// TODO hugepages?
	// TODO hotplug memory?

	o.vmconfig.ProcessorConfig.ProcessorLimit = uint32(o.config.DefaultMaxVCPUs)
	o.vmconfig.ProcessorConfig.ProcessorCount = uint32(o.config.NumVCPUs())

	// TODO disableNvdimm?
	disableNvdimm := (o.config.DisableImageNvdimm || o.config.ConfidentialGuest)
	// TODO enableDax?
	enableDax := !disableNvdimm

	params, err := openvmmGetNonUserDefinedKernelParams(hypervisorConfig.RootfsType, disableNvdimm, enableDax, o.config.Debug, o.config.ConfidentialGuest, o.config.IOMMU)
	if err != nil {
		return err
	}
	// Followed by extra kernel parameters defined in the configuration file
	params = append(params, o.config.KernelParams...)

	o.vmconfig.GetDirectBoot().KernelCmdline = strings.Join(SerializeParams(params, "="), " ")

	// TODO RNG device?
	// TODO serial config?

	// Overwrite the default value of gRPC API socket path for OpenVMM
	apiSocketPath, err := o.apiSocketPath(id)
	if err != nil {
		o.Logger().WithError(err).Info("Invalid api socket path for openvmm")
		return err
	}
	o.state.apiSocket = apiSocketPath

	// Establish gRPC connection to OpenVMM
	conn, err := grpc.NewClient("unix://"+o.state.apiSocket, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to connect to OpenVMM: %w", err)
	}
	o.grpcConn = conn
	o.grpcClient = openvmmservice.NewVMClient(o.grpcConn)
	return nil
}

func (o *openvmm) AddDevice(ctx context.Context, devInfo interface{}, devType DeviceType) error {
	span, _ := katatrace.Trace(ctx, o.Logger(), "AddDevice", openvmmTracingTags, map[string]string{"sandbox_id": o.id})
	defer span.End()

	var err error

	switch v := devInfo.(type) {
	case Endpoint:
		err = o.addNet(v)
	case types.HybridVSock:
		err = o.addVSock(v.UdsPath)
	default:
		o.Logger().WithField("function", "AddDevice").Warnf("Add device of type %v is not supported.", v)
		return fmt.Errorf("Not implemented support for %s", v)
	}

	return err
}

func (o *openvmm) HotplugAddDevice(ctx context.Context, devInfo interface{}, devType DeviceType) (interface{}, error) {
	span, _ := katatrace.Trace(ctx, o.Logger(), "HotplugAddDevice", openvmmTracingTags, map[string]string{"sandbox_id": o.id})
	defer span.End()

	switch devType {
	case BlockDev:
		drive := devInfo.(*config.BlockDrive)
		return nil, clh.hotplugAddBlockDevice(drive)
	case VfioDev:
		device := devInfo.(*config.VFIODev)
		return nil, clh.hotPlugVFIODevice(device)
	case NetDev:
		device := devInfo.(Endpoint)
		return nil, clh.hotplugAddNetDevice(device)
	default:
		return nil, fmt.Errorf("cannot hotplug device: unsupported device type '%v'", devType)
	}

}

// Adds all capabilities supported by openvmm implementation of hypervisor interface
func (o *openvmm) Capabilities(ctx context.Context) types.Capabilities {
	span, _ := katatrace.Trace(ctx, o.Logger(), "Capabilities", openvmmTracingTags, map[string]string{"sandbox_id": o.id})
	defer span.End()

	o.Logger().WithField("function", "Capabilities").Info("get Capabilities")
	var caps types.Capabilities
	caps.SetBlockDeviceSupport()
	caps.SetBlockDeviceHotplugSupport()
	caps.SetNetworkDeviceHotplugSupported()
	return caps
}

func (o *openvmm) Check() error {
	// Use a long timeout to check if the VMM is running:
	// Check is used by the monitor thread(a background thread). If the
	// monitor thread calls Check() during the Container boot, it will take
	// longer than usual specially if there is a hot-plug request in progress.
	running, err := o.isOpenvmmRunning(10)
	if !running {
		return fmt.Errorf("openvmm is not running: %s", err)
	}
	return err
}

func (o *openvmm) GenerateSocket(id string) (interface{}, error) {
	udsPath, err := o.vsockSocketPath(id)
	if err != nil {
		o.Logger().Info("Can't generate socket path for cloud-hypervisor")
		return types.HybridVSock{}, err
	}

	return types.HybridVSock{
		UdsPath: udsPath,
		Port:    uint32(vSockPort),
	}, nil
}

// TODO!! Not yet sure where the vcpu threads are...
func (o *openvmm) GetThreadIDs(ctx context.Context) (VcpuThreadIDs, error) {

	o.Logger().WithField("function", "GetThreadIDs").Info("get thread ID's")

	var vcpuInfo VcpuThreadIDs

	vcpuInfo.vcpus = make(map[int]int)

	getVcpus := func(pid int) (map[int]int, error) {
		vcpus := make(map[int]int)

		dir := fmt.Sprintf("/proc/%d/task", pid)
		files, err := os.ReadDir(dir)
		if err != nil {
			return vcpus, err
		}

		pattern, err := regexp.Compile(`^vcpu\d+$`)
		if err != nil {
			return vcpus, err
		}
		for _, file := range files {
			comm, err := os.ReadFile(fmt.Sprintf("%s/%s/comm", dir, file.Name()))
			if err != nil {
				return vcpus, err
			}
			pName := strings.TrimSpace(string(comm))
			if !pattern.MatchString(pName) {
				continue
			}

			cpuID := strings.TrimPrefix(pName, "vcpu")
			threadID := file.Name()

			k, err := strconv.Atoi(cpuID)
			if err != nil {
				return vcpus, err
			}
			v, err := strconv.Atoi(threadID)
			if err != nil {
				return vcpus, err
			}
			vcpus[k] = v
		}
		return vcpus, nil
	}

	if o.state.PID == 0 {
		return vcpuInfo, nil
	}

	vcpus, err := getVcpus(o.state.PID)
	if err != nil {
		return vcpuInfo, err
	}
	vcpuInfo.vcpus = vcpus

	return vcpuInfo, nil
}

func (o *openvmm) GetTotalMemoryMB(ctx context.Context) uint32 {
	memory, _, err := o.vmInfo()
	if err != nil {
		o.Logger().WithError(err).Error("failed to get vminfo")
		return 0
	}

	return uint32(memory.WorkingSetBytes)
}

// GetVMConsole builds the path of the console where we can read logs coming
// from the sandbox.
func (o *openvmm) GetVMConsole(ctx context.Context, id string) (string, string, error) {
	o.Logger().WithField("function", "GetVMConsole").WithField("id", id).Info("Get Sandbox Console")
	master, slave, err := console.NewPty()
	if err != nil {
		o.Logger().WithError(err).Error("Error create pseudo tty")
		return consoleProtoPty, "", err
	}
	o.console = master

	return consoleProtoPty, slave, nil
}

func (o *openvmm) GetVirtioFsPid() *int {
	return &o.state.VirtiofsDaemonPid
}

func (o *openvmm) GetPids() []int {
	return []int{o.state.PID}
}

func (o *openvmm) Cleanup(ctx context.Context) error {
	o.Logger().WithField("function", "Cleanup").Info("Cleanup")
	return nil
}

func (o *openvmm) PauseVM(ctx context.Context) error {
	o.Logger().WithField("function", "PauseVM").Info("Pause Sandbox")
	return nil
}

func (o *openvmm) SaveVM() error {
	o.Logger().WithField("function", "saveSandboxC").Info("Save Sandbox")
	return nil
}

func (o *openvmm) ResumeVM(ctx context.Context) error {
	o.Logger().WithField("function", "ResumeVM").Info("Resume Sandbox")
	return nil
}

func (o *openvmm) Disconnect(ctx context.Context) {
	o.Logger().WithField("function", "Disconnect").Info("Disconnecting Sandbox Console")
}

//###########################################################################
//
// Local methods related to grpc interface implementation
//
//###########################################################################

// getVMCapabilities demonstrates calling a client method
func (o *openvmm) getVMCapabilities(ctx context.Context) (*openvmmservice.CapabilitiesVMResponse, error) {
	if o.grpcClient == nil {
		return nil, fmt.Errorf("VM client not initialized")
	}

	// Call the CapabilitiesVM method
	response, err := o.grpcClient.CapabilitiesVM(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to get VM capabilities: %w", err)
	}

	return response, nil
}

// pauseVM demonstrates calling PauseVM method
func (o *openvmm) pauseVM(ctx context.Context) error {
	if o.grpcClient == nil {
		return fmt.Errorf("VM client not initialized")
	}

	// Call the PauseVM method
	_, err := o.grpcClient.PauseVM(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("failed to pause VM: %w", err)
	}

	return nil
}

// resumeVM demonstrates calling ResumeVM method
func (o *openvmm) resumeVM(ctx context.Context) error {
	if o.grpcClient == nil {
		return fmt.Errorf("VM client not initialized")
	}

	// Call the ResumeVM method
	_, err := o.grpcClient.ResumeVM(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("failed to resume VM: %w", err)
	}

	return nil
}

// teardownVM demonstrates calling TeardownVM method
func (o *openvmm) teardownVM(ctx context.Context) error {
	if o.grpcClient == nil {
		return fmt.Errorf("VM client not initialized")
	}

	// Call the TeardownVM method
	_, err := o.grpcClient.TeardownVM(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("failed to teardown VM: %w", err)
	}

	return nil
}

// disconnect closes the gRPC connection
func (o *openvmm) disconnect() error {
	if o.grpcConn != nil {
		err := o.grpcConn.Close()
		o.grpcConn = nil
		o.grpcClient = nil
		return err
	}
	return nil
}

func (o *openvmm) isOpenvmmRunning(timeout uint) (bool, error) {

	pid := o.state.PID

	if atomic.LoadInt32(&o.stopped) != 0 {
		return false, nil
	}

	timeStart := time.Now()
	for {
		waitedPid, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil)
		if waitedPid == pid && err == nil {
			return false, nil
		}

		err = syscall.Kill(pid, syscall.Signal(0))
		if err != nil {
			return false, nil
		}
		state := o.grpcConn.GetState()
		if state == connectivity.Ready {
			return true, nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), openvmmGRPCTimeout*time.Second)
		o.grpcConn.WaitForStateChange(ctx, state)
		cancel()

		state = o.grpcConn.GetState()
		if state == connectivity.Ready {
			return true, nil
		} else {
			o.Logger().WithError(err).Warningf("openvmm GRPC connection unexpected state: %s", state)
		}

		if time.Since(timeStart).Seconds() > float64(timeout) {
			return false, fmt.Errorf("Failed to connect to GRPC server (timeout %ds): %s", timeout, err)
		}

		time.Sleep(time.Duration(10) * time.Millisecond)
	}
}

//###########################################################################
//
// Local helper methods related to the openvmm interface implementation
//
//###########################################################################

func (o *openvmm) Logger() *log.Entry {
	return hvLogger.WithField("subsystem", "openvmm")
}

// createDefaultVMConfig creates a default VMConfig with basic settings
func (o *openvmm) createDefaultVMConfig() *openvmmservice.VMConfig {
	return &openvmmservice.VMConfig{
		MemoryConfig: &openvmmservice.MemoryConfig{
			// Default to 2GB RAM
			MemoryMb: 2048,
		},
		ProcessorConfig: &openvmmservice.ProcessorConfig{
			// Default to 2 vCPUs
			ProcessorCount: 2,
		},
		DevicesConfig: &openvmmservice.DevicesConfig{
			// Add default devices as needed
		},
		SerialConfig: &openvmmservice.SerialConfig{
			Ports: []*openvmmservice.SerialConfig_Config{
				{
					Port:       0,  // Default serial port number (0 = COM1/ttyS0)
					SocketPath: "", // Default socket path for serial console
				},
			},
		},
		// Set direct boot as default (you can change this to UEFI if needed)
		BootConfig: &openvmmservice.VMConfig_DirectBoot{
			DirectBoot: &openvmmservice.DirectBoot{
				// Will be set later from hypervisor config
				KernelPath:    "",
				InitrdPath:    "",
				KernelCmdline: "",
			},
		},
		ExtraData: make(map[string]string),
	}
}

func (o *openvmm) vsockSocketPath(id string) (string, error) {
	return utils.BuildSocketPath(o.config.VMStorePath, id, openvmmVSocket)
}

func (o *openvmm) apiSocketPath(id string) (string, error) {
	return utils.BuildSocketPath(o.config.VMStorePath, id, openvmmAPISocket)
}

func (o *openvmm) addNet(e Endpoint) error {
	o.Logger().WithField("endpoint", e).Debugf("Adding Endpoint of type %v", e.Type())

	mac := e.HardwareAddr()
	netPair := e.NetworkPair()
	if netPair == nil {
		return errors.New("net Pair to be added is nil, needed to get TAP file descriptors")
	}

	if len(netPair.TapInterface.VMFds) == 0 {
		return errors.New("The file descriptors for the network pair are not present")
	}
	o.netDevicesFiles[mac] = netPair.TapInterface.VMFds

	net := o.newNICConfig(mac)

	o.netDevices = append(o.netDevices, net)

	o.Logger().Infof("Storing the OpenVMM network configuration: %+v", net)

	return nil
}

func (o *openvmm) newNICConfig(mac string) *openvmmservice.NICConfig {
	guid := uuid.New().String()
	net := &openvmmservice.NICConfig{
		NicId:      guid,
		MacAddress: mac,
		Backend: &openvmmservice.NICConfig_Tap{
			Tap: &openvmmservice.TapBackend{
				Name: "tap" + guid,
			},
		},
	}

	return net
}

func (o *openvmm) addVSock(path string) error {
	if path == "" {
		return fmt.Errorf("invalid path for HybridVSock: %s", path)
	}

	o.Logger().WithFields(log.Fields{
		"path": path,
	}).Info("Adding HybridVSock")

	o.vmconfig.HvsocketConfig = &openvmmservice.HVSocketConfig{
		Path: path,
	}

	return nil
}

// TODO: the PropertiesVM grpc is not yet implemented in openvmm, return mock values
func (o *openvmm) vmInfo() (openvmmservice.MemoryStats, openvmmservice.ProcessorStats, error) {
	return openvmmservice.MemoryStats{
			WorkingSetBytes: 2048,
			AvailableMemory: 2048,
		}, openvmmservice.ProcessorStats{
			TotalRuntimeNs: 2000000000, // 2 seconds
		}, nil
}
