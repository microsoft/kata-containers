package virtcontainers

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	openvmmservice "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/openvmm/protos"
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

// openvmm represents the OpenVMM hypervisor
type openvmm struct {
	id     string
	state  openvmmState
	config HypervisorConfig
	client openvmmservice.VMClient
	conn   *grpc.ClientConn
}

// connectToOpenVMM establishes a gRPC connection and creates a VM client
func (o *openvmm) connectToOpenVMM(socketPath string) error {
	// Establish gRPC connection to OpenVMM
	conn, err := grpc.Dial("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to OpenVMM: %w", err)
	}

	// Create VM client using NewVMClient
	client := openvmmservice.NewVMClient(conn)

	// Store connection and client
	o.conn = conn
	o.client = client

	return nil
}

// getVMCapabilities demonstrates calling a client method
func (o *openvmm) getVMCapabilities(ctx context.Context) (*openvmmservice.CapabilitiesVMResponse, error) {
	if o.client == nil {
		return nil, fmt.Errorf("VM client not initialized")
	}

	// Call the CapabilitiesVM method
	response, err := o.client.CapabilitiesVM(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to get VM capabilities: %w", err)
	}

	return response, nil
}

// createVM demonstrates calling CreateVM method
func (o *openvmm) createVM(ctx context.Context, config *openvmmservice.CreateVMRequest) error {
	if o.client == nil {
		return fmt.Errorf("VM client not initialized")
	}

	// Call the CreateVM method
	_, err := o.client.CreateVM(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}

	o.state = openvmmReady
	return nil
}

// pauseVM demonstrates calling PauseVM method
func (o *openvmm) pauseVM(ctx context.Context) error {
	if o.client == nil {
		return fmt.Errorf("VM client not initialized")
	}

	// Call the PauseVM method
	_, err := o.client.PauseVM(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("failed to pause VM: %w", err)
	}

	return nil
}

// resumeVM demonstrates calling ResumeVM method
func (o *openvmm) resumeVM(ctx context.Context) error {
	if o.client == nil {
		return fmt.Errorf("VM client not initialized")
	}

	// Call the ResumeVM method
	_, err := o.client.ResumeVM(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("failed to resume VM: %w", err)
	}

	return nil
}

// teardownVM demonstrates calling TeardownVM method
func (o *openvmm) teardownVM(ctx context.Context) error {
	if o.client == nil {
		return fmt.Errorf("VM client not initialized")
	}

	// Call the TeardownVM method
	_, err := o.client.TeardownVM(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("failed to teardown VM: %w", err)
	}

	return nil
}

// disconnect closes the gRPC connection
func (o *openvmm) disconnect() error {
	if o.conn != nil {
		err := o.conn.Close()
		o.conn = nil
		o.client = nil
		return err
	}
	return nil
}

// Example usage function showing the complete workflow
func ExampleOpenVMMUsage() error {
	ctx := context.Background()

	// Create openvmm instance
	hypervisor := &openvmm{
		id:    "example-vm",
		state: openvmmNotReady,
	}

	// Connect to OpenVMM service
	err := hypervisor.connectToOpenVMM("/var/run/openvmm.sock")
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer hypervisor.disconnect()

	// Get VM capabilities
	capabilities, err := hypervisor.getVMCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("failed to get capabilities: %w", err)
	}

	fmt.Printf("VM Capabilities retrieved successfully: %+v\n", capabilities)

	// Example: Create VM with configuration
	// vmConfig := &openvmmservice.CreateVMRequest{
	//     // Add your VM configuration here
	// }
	// err = hypervisor.createVM(ctx, vmConfig)
	// if err != nil {
	//     return fmt.Errorf("failed to create VM: %w", err)
	// }

	// Example: Pause VM
	// err = hypervisor.pauseVM(ctx)
	// if err != nil {
	//     return fmt.Errorf("failed to pause VM: %w", err)
	// }

	// Example: Resume VM
	// err = hypervisor.resumeVM(ctx)
	// if err != nil {
	//     return fmt.Errorf("failed to resume VM: %w", err)
	// }

	return nil
}
