package virtcontainers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/config"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/annotations"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

var (
	// Key:  API name to test
	// Value:struct implementing the CallTtrpcReq interface
	// This allows to implement only the Unmarshaler interface (and not the Marshaler) since we
	// can use the 'Api' field in the JSON encoded object.
	apiMap = map[string]reflect.Type{
		"CreateContainerRequest": reflect.TypeOf(CreateContainerReq{}),
		"StartContainerRequest":  reflect.TypeOf(StartContainerReq{}),
		"RemoveContainerRequest": reflect.TypeOf(RemoveContainerReq{}),
		"CopyFileRequest":        reflect.TypeOf(CopyFileReq{}),
		"SetPolicyRequest":       reflect.TypeOf(SetPolicyReq{}),
	}

	// to enable more verbose logging
	logger = logrus.WithFields(logrus.Fields{"test-agent-api": "logs"})
)

// Defining an Interface for testing the Agent Ttrpc API request by forwarding to a virtcontainers endpoint.
type CallTtrpcReq interface {
	CallApi(context.Context, VCSandbox) error
}

// Base Struct for each Request
type TtrpcTestReq struct {
	Api       string
	SandboxID string
	Params    CallTtrpcReq
}

// Agent API: CreateContainerRequest
type CreateContainerReq struct {
	Id            string
	RootfsOptions string
	Config        string
	Snapshotter   string
}

// Agent API: StartContainerRequest
type StartContainerReq struct {
	Id string
}

// Agent API: RemoveContainerRequest
type RemoveContainerReq struct {
	Id string
}

// Agent API: CopyFileRequest
type CopyFileReq struct {
	Src  string
	Dest string
}

// Agent API: SetPolicy
type SetPolicyReq struct {
	Buf []byte
}

func newMount(m specs.Mount) Mount {
	readonly := false
	bind := false
	for _, flag := range m.Options {
		switch flag {
		case "rbind", "bind":
			bind = true
		case "ro":
			readonly = true
		}
	}

	mountType := m.Type
	if mountType != KataEphemeralDevType && mountType != KataLocalDevType && bind {
		mountType = "bind"
	}

	return Mount{
		Source:      m.Source,
		Destination: m.Destination,
		Type:        mountType,
		Options:     m.Options,
		ReadOnly:    readonly,
	}
}

func getContainerMounts(spec specs.Spec) []Mount {
	ociMounts := spec.Mounts

	if ociMounts == nil {
		return []Mount{}
	}

	var mnts []Mount
	for _, m := range ociMounts {
		mnts = append(mnts, newMount(m))
	}

	return mnts
}

func contains(strings []string, toFind string) bool {
	for _, candidate := range strings {
		if candidate == toFind {
			return true
		}
	}
	return false
}

func newLinuxDeviceInfo(d specs.LinuxDevice) (*config.DeviceInfo, error) {
	allowedDeviceTypes := []string{"c", "b", "u", "p"}

	if !contains(allowedDeviceTypes, d.Type) {
		return nil, fmt.Errorf("test-agent-api: Unexpected Device Type %s for device %s", d.Type, d.Path)
	}

	if d.Path == "" {
		return nil, fmt.Errorf("test-agent-api: Path cannot be empty for device")
	}

	deviceInfo := config.DeviceInfo{
		ContainerPath: d.Path,
		DevType:       d.Type,
		Major:         d.Major,
		Minor:         d.Minor,
	}
	if d.UID != nil {
		deviceInfo.UID = *d.UID
	}

	if d.GID != nil {
		deviceInfo.GID = *d.GID
	}

	if d.FileMode != nil {
		deviceInfo.FileMode = *d.FileMode
	}

	return &deviceInfo, nil
}

func getContainerDeviceInfos(spec specs.Spec) ([]config.DeviceInfo, error) {
	ociLinuxDevices := spec.Linux.Devices

	if ociLinuxDevices == nil {
		return []config.DeviceInfo{}, nil
	}

	var devices []config.DeviceInfo
	for _, d := range ociLinuxDevices {
		linuxDeviceInfo, err := newLinuxDeviceInfo(d)
		if err != nil {
			return []config.DeviceInfo{}, err
		}

		devices = append(devices, *linuxDeviceInfo)
	}

	return devices, nil
}

func cmdEnvs(spec specs.Spec, envs []types.EnvVar) []types.EnvVar {
	for _, env := range spec.Process.Env {
		kv := strings.Split(env, "=")
		if len(kv) < 2 {
			continue
		}

		envs = append(envs,
			types.EnvVar{
				Var:   kv[0],
				Value: kv[1],
			})
	}

	return envs
}

func containerConfigHelper(ocispec specs.Spec, bundlePath, cid string, detach bool) (ContainerConfig, error) {
	rootfs := RootFs{Target: ocispec.Root.Path, Mounted: true}
	if !filepath.IsAbs(rootfs.Target) {
		rootfs.Target = filepath.Join(bundlePath, ocispec.Root.Path)
	}

	cmd := types.Cmd{
		Args:            ocispec.Process.Args,
		Envs:            cmdEnvs(ocispec, []types.EnvVar{}),
		WorkDir:         ocispec.Process.Cwd,
		User:            strconv.FormatUint(uint64(ocispec.Process.User.UID), 10),
		PrimaryGroup:    strconv.FormatUint(uint64(ocispec.Process.User.GID), 10),
		Interactive:     ocispec.Process.Terminal,
		Detach:          detach,
		NoNewPrivileges: ocispec.Process.NoNewPrivileges,
	}

	cmd.SupplementaryGroups = []string{}
	for _, gid := range ocispec.Process.User.AdditionalGids {
		cmd.SupplementaryGroups = append(cmd.SupplementaryGroups, strconv.FormatUint(uint64(gid), 10))
	}

	deviceInfos, err := getContainerDeviceInfos(ocispec)
	if err != nil {
		return ContainerConfig{}, err
	}

	if ocispec.Process != nil {
		cmd.Capabilities = ocispec.Process.Capabilities
	}

	containerConfig := ContainerConfig{
		ID:             cid,
		RootFs:         rootfs,
		ReadonlyRootfs: ocispec.Root.Readonly,
		Cmd:            cmd,
		Annotations:    ocispec.Annotations,
		Mounts:         getContainerMounts(ocispec),
		DeviceInfos:    deviceInfos,
		Resources:      *ocispec.Linux.Resources,

		// This is a custom OCI spec modified at SetEphemeralStorageType()
		// to support ephemeral storage and k8s empty dir.
		CustomSpec: &ocispec,
	}
	if containerConfig.Annotations == nil {
		containerConfig.Annotations = map[string]string{
			annotations.BundlePathKey: bundlePath,
		}
	} else {
		containerConfig.Annotations[annotations.BundlePathKey] = bundlePath
	}

	//TO-DO: We are not using this for creating infra container, so type is fixed.
	cType := PodContainer

	containerConfig.Annotations[annotations.ContainerTypeKey] = string(cType)

	return containerConfig, nil
}

// Helper function copied from: 'src/runtime/pkg/containerd-shim-v2/create.go'
func copyLayersToMountsHelper(opts []string, spec *specs.Spec) error {
	prefix := ""
	for _, o := range opts {
		if strings.HasPrefix(o, annotations.FileSystemLayerSourcePrefix) {
			prefix = o[len(annotations.FileSystemLayerSourcePrefix):]
			continue
		}

		if !strings.HasPrefix(o, annotations.FileSystemLayer) {
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(o[len(annotations.FileSystemLayer):])
		if err != nil {
			return fmt.Errorf("Unable to decode layer %q: %w", o, err)
		}

		fields := strings.Split(string(decoded), ",")
		if len(fields) < 2 {
			return fmt.Errorf("Missing fields in rootfs layer: %q", o)
		}

		source := fields[0]
		if len(source) > 0 && source[0] != '/' {
			source = filepath.Join(prefix, source)
		}

		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/run/kata-containers/sandbox/layers/" + filepath.Base(source),
			Type:        fields[1],
			Source:      source,
			Options:     fields[2:],
		})
	}

	return nil
}

func getAgentInterface(sandbox VCSandbox) any {
	var agentVal = reflect.Indirect(reflect.ValueOf(sandbox)).FieldByName("agent")
	var unsafeVal = reflect.NewAt(agentVal.Type(), unsafe.Pointer(agentVal.UnsafeAddr())).Elem()
	return unsafeVal.Interface()
}

func (cc CreateContainerReq) CallApi(ctx context.Context, sandbox VCSandbox) error {
	logrus.Error("DEBUG: test-agent-api: testing createContainer api")

	logger.WithFields(logrus.Fields{"container id": fmt.Sprintf("%s", cc.Id)}).Error("Debug: test-agent api ")
	logger.WithFields(logrus.Fields{"rootfs options": fmt.Sprintf("%s", cc.RootfsOptions)}).Error("Debug: test-agent api ")
	logger.WithFields(logrus.Fields{"config file path": fmt.Sprintf("%s", cc.Config)}).Error("Debug: test-agent api ")
	logger.WithFields(logrus.Fields{"snapshotter ": fmt.Sprintf("%s", cc.Snapshotter)}).Error("Debug: test-agent api ")

	disableGuestEmptyDirLocal := false

	//Only support tardev-snapshotter & equivalent args.
	if strings.Compare(cc.Snapshotter, "tardev-snapshotter") != 0 {
		logrus.Error("TestCreateContainer: only supports tardev-snapshotter")
		return errors.New("CreateContainer: unsupported snapshotter")
	}

	//Parse the supplied config.json to a oci equivalent spec
	//We do not get any bundlePath equivalent. Treat the parent directory as the equivalent bundle dir
	bundlePath := filepath.Dir(cc.Config)
	ociSpec, err := compatoci.ParseConfigJSON(bundlePath)
	if err != nil {
		logrus.Error("TestCreateContainer: failed to Parse config json.")
		return err
	}

	//Fix the oci spec mount options based on the rootfs options received.
	rootfsOptsArr := strings.Fields(cc.RootfsOptions)
	if err := copyLayersToMountsHelper(rootfsOptsArr, &ociSpec); err != nil {
		logrus.Error("TestCreateContainer: Failed to add layers information to oci spec mounts")
		return err
	}

	//Set default rootFs values
	rootFs := RootFs{}
	rootFs.Source = "/"
	rootFs.Type = "fuse3.kata-overlay"
	rootFs.Options = rootfsOptsArr
	rootFs.Mounted = false

	//Additional work
	delete(ociSpec.Annotations, annotations.Policy)

	//Setup ephemeral mount points
	for idx, mnt := range ociSpec.Mounts {
		if IsEphemeralStorage(mnt.Source) {
			ociSpec.Mounts[idx].Type = KataEphemeralDevType
		}
		if Isk8sHostEmptyDir(mnt.Source) && !disableGuestEmptyDirLocal {
			ociSpec.Mounts[idx].Type = KataLocalDevType
		}
	}

	//// ContainerConfig describes one container runtime configuration.
	contConfig, err := containerConfigHelper(ociSpec, bundlePath, cc.Id, false)
	contConfig.RootFs = rootFs

	container, err := sandbox.CreateContainer(ctx, contConfig)
	if err != nil {
		return err
	}

	//TO-DO: NO pre-start OCI hooks.
	err = EnterNetNS(sandbox.GetNetNs(), func() error {
		return nil
	})

	if err != nil {
		return err
	}

	logrus.Error("Something HAPPENED, process: ", container.Process().Pid)
	return nil
}

func (sc StartContainerReq) CallApi(ctx context.Context, sandbox VCSandbox) error {
	logrus.Error("DEBUG: test-agent-api: StartContainer for ", sc.Id)

	//TO-DO: For now, only support starting non-infra containers
	container, err := sandbox.StartContainer(ctx, sc.Id)
	if err != nil {
		logrus.Error("Failed to start the container process")
		return err
	}

	logrus.Error("Container started... ", container.Process().Pid)
	return nil
}

func (rc RemoveContainerReq) CallApi(ctx context.Context, sandbox VCSandbox) error {
	logrus.Error("DEBUG: test-agent-api: RemoveContainer for ", rc.Id)

	//TO-DO: For now, only support removing non-infra containers
	_, err := sandbox.StopContainer(ctx, rc.Id, false)
	if err != nil && !(err == types.ErrNoSuchContainer || err == syscall.ENOENT ||
		strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not exist")) {
		logrus.Error("Failed to stop container")
		return err
	}

	_, err = sandbox.DeleteContainer(ctx, rc.Id)
	if err != nil && !(err == types.ErrNoSuchContainer || err == syscall.ENOENT ||
		strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not exist")) {
		logrus.Error("Failed to delete container from sandbox")
		return err
	}

	return nil
}

func (cp CopyFileReq) CallApi(ctx context.Context, sandbox VCSandbox) error {
	logrus.Error("DEBUG: test-agent-api: testing copyFile Api")
	return getAgentInterface(sandbox).(*kataAgent).copyFile(ctx, cp.Src, cp.Dest)
}

func (sp SetPolicyReq) CallApi(ctx context.Context, sandbox VCSandbox) error {
	logrus.Error("DEBUG: test-agent-api: testing setPolicy Api")
	return getAgentInterface(sandbox).(*kataAgent).setPolicy(ctx, string(sp.Buf))
}

// Implement Unmarshaller for TtrpcTestReq
func (ttreq *TtrpcTestReq) UnmarshalJSON(b []byte) error {
	var data struct {
		Api       string
		SandboxID string
		Params    json.RawMessage
	}

	if err := json.Unmarshal(b, &data); err != nil {
		logger.Error("DEBUG: test-agent-api: failed to unmarshal JSON to custom object.")
		return err
	}

	if apiHandlerType, found := apiMap[data.Api]; found {
		handlerType := reflect.New(apiHandlerType)

		if err := json.Unmarshal(data.Params, handlerType.Interface()); err != nil {
			logger.Error("DEBUG: test-agent-api: failed to unmarshal JSON for Params field.")
			return err
		}

		ttreq.Params = handlerType.Elem().Interface().(CallTtrpcReq)
		return nil
	}

	logger.WithFields(logrus.Fields{"api": fmt.Sprintf("%s", data.Api)}).Error("DEBUG: test-agent-api: Agent Api is not valid")

	return errors.New("test-agent-api: Failed to unmarshal encoded JSON")
}

func TestApi(ctx context.Context, input []byte, sandbox VCSandbox) error {
	// Unmarshal the request. We need to implement Unmarshaller since the request struct has one field as interface
	request := TtrpcTestReq{}

	// TtrpcTestReq struct implements Unmarshaller interface.
	// This is needed since the struct has a field of interface type.
	if err := json.Unmarshal(input, &request); err != nil {
		return err
	}

	// Call the API
	if err := request.Params.CallApi(ctx, sandbox); err != nil {
		return err
	}

	return nil
}
