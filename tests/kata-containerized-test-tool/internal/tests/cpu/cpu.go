package cpu

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/kata-containers/tests/kata-containerized-test-tool/internal/core"
)

type CPUTest struct{}

func New() *CPUTest {
	return &CPUTest{}
}

func (t *CPUTest) Name() string {
	return "cpu"
}

func (t *CPUTest) Run(ctx context.Context, expectedValues map[string]interface{}) core.TestResult {
	result := core.TestResult{
		Name:           t.Name(),
		StartTime:      time.Now(),
		Metrics:        make(map[string]interface{}),
		ExpectedValues: expectedValues,
		Success:        true, // Default to success if no expected values
	}

	// Get actual CPU count
	cpuCount := runtime.NumCPU()
	result.Metrics["vcpu_count"] = cpuCount

	// Check against expected values if provided
	if expectedCPU, exists := expectedValues["expected_vcpu_count"]; exists {
		if expectedCount, ok := expectedCPU.(float64); ok {
			if int(expectedCount) != cpuCount {
				result.Success = false
				result.Error = fmt.Sprintf("Expected %d vCPUs, found %d", int(expectedCount), cpuCount)
			}
		}
	}

	result.EndTime = time.Now()
	return result
}
