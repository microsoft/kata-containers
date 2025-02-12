package cpu

import (
    "context"
    "runtime"
    "time"
    "fmt"
    
    "github.com/shirou/gopsutil/v3/cpu"
    "github.com/kata-containers/tests/kata-containerized-test-tool/internal/core"
)

type CPUTest struct{}

func New() *CPUTest {
    return &CPUTest{}
}

func (t *CPUTest) Name() string {
    return "CPU Count Test"
}

func (t *CPUTest) Run(ctx context.Context) core.TestResult {
    result := core.TestResult{
        Name:      t.Name(),
        StartTime: time.Now(),
        Metrics:   make(map[string]interface{}),
    }
    
    // Get CPU count using different methods
    result.Metrics["runtime_cpu_count"] = runtime.NumCPU()
    
    if cpuInfo, err := cpu.Info(); err == nil {
        result.Metrics["physical_cpu_count"] = len(cpuInfo)
        result.Success = true
    } else {
        result.Error = fmt.Sprintf("Failed to get CPU info: %v", err)
        result.Success = false
    }
    
    result.EndTime = time.Now()
    return result
}