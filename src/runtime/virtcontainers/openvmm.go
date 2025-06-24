package virtcontainers

// openvmmTracingTags defines tags for the trace span
var openvmmTracingTags = map[string]string{
	"source":    "runtime",
	"package":   "virtcontainers",
	"subsystem": "hypervisor",
	"type":      "openvmm",
}

//
// Constants and type definitions related to cloud hypervisor
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
	// Values are mandatory by http API
	// Values based on:
	clhTimeout                     = 10
	clhAPITimeout                  = 1
	clhAPITimeoutConfidentialGuest = 20
	// Minimum timout for calling CreateVM followed by BootVM. Executing these two APIs
	// might take longer than the value returned by getClhAPITimeout().
	clhCreateAndBootVMMinimumTimeout = 10
	// Timeout for hot-plug - hotplug devices can take more time, than usual API calls
	// Use longer time timeout for it.
	clhHotPlugAPITimeout                   = 5
	clhStopSandboxTimeout                  = 3
	clhStopSandboxTimeoutConfidentialGuest = 10
	clhSocket                              = "clh.sock"
	clhAPISocket                           = "clh-api.sock"
	virtioFsSocket                         = "virtiofsd.sock"
	defaultClhPath                         = "/usr/local/bin/cloud-hypervisor"
)