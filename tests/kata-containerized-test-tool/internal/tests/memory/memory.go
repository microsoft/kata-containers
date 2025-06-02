package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/kata-containers/tests/kata-containerized-test-tool/internal/core"
	"github.com/shirou/gopsutil/v3/mem"
)

type MemoryTest struct{}

func New() *MemoryTest {
	return &MemoryTest{}
}

func (t *MemoryTest) Name() string {
	return "memory"
}

func (t *MemoryTest) Run(ctx context.Context, expectedValues map[string]interface{}) core.TestResult {
	result := core.TestResult{
		Name:           t.Name(),
		StartTime:      time.Now(),
		Metrics:        make(map[string]interface{}),
		ExpectedValues: expectedValues,
		Success:        true, // Default to success if no expected values
	}

	// Get memory metrics
	vm, err := mem.VirtualMemory()
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to get memory info: %v", err)
		result.EndTime = time.Now()
		return result
	}

	totalMemoryMB := vm.Total / (1024 * 1024)
	result.Metrics["total_memory_mb"] = totalMemoryMB

	// Check against expected values if provided
	if expectedMem, exists := expectedValues["expected_memory_mb"]; exists {
		if expectedMemMB, ok := expectedMem.(float64); ok {
			// Allow 5% tolerance
			tolerance := float64(totalMemoryMB) * 0.05
			if float64(totalMemoryMB) < (expectedMemMB-tolerance) ||
				float64(totalMemoryMB) > (expectedMemMB+tolerance) {
				result.Success = false
				result.Error = fmt.Sprintf("Expected %d MB memory (±5%%), found %d MB",
					int(expectedMemMB), totalMemoryMB)
			}
		}
	}

	result.EndTime = time.Now()
	return result
}
