package memory

import (
    "context"
    "fmt"
    "time"
    "os"
    
    "github.com/shirou/gopsutil/v3/mem"
    "github.com/kata-containers/tests/kata-containerized-test-tool/internal/core"
)

type MemoryTest struct{}

func New() *MemoryTest {
    return &MemoryTest{}
}

func (t *MemoryTest) Name() string {
    return "Memory Allocation Test"
}

func (t *MemoryTest) Run(ctx context.Context) core.TestResult {
    result := core.TestResult{
        Name:      t.Name(),
        StartTime: time.Now(),
        Metrics:   make(map[string]interface{}),
    }

    // Get virtual memory stats
    vmStats, err := mem.VirtualMemory()
    if err != nil {
        result.Error = fmt.Sprintf("Failed to get virtual memory stats: %v", err)
        result.Success = false
        result.EndTime = time.Now()
        return result
    }

    // Get swap memory stats
    swapStats, err := mem.SwapMemory()
    if err != nil {
        result.Error = fmt.Sprintf("Failed to get swap memory stats: %v", err)
        result.Success = false
        result.EndTime = time.Now()
        return result
    }

    // Store memory metrics
    result.Metrics["total_memory"] = vmStats.Total
    result.Metrics["available_memory"] = vmStats.Available
    result.Metrics["used_memory"] = vmStats.Used
    result.Metrics["free_memory"] = vmStats.Free
    result.Metrics["memory_usage_percent"] = vmStats.UsedPercent
    
    // Swap metrics
    result.Metrics["total_swap"] = swapStats.Total
    result.Metrics["used_swap"] = swapStats.Used
    result.Metrics["free_swap"] = swapStats.Free
    result.Metrics["swap_usage_percent"] = swapStats.UsedPercent

    // Check cgroup memory limits if available
    cgroupMemory, err := t.getCgroupMemoryLimit()
    if err == nil {
        result.Metrics["cgroup_memory_limit"] = cgroupMemory
    }

    result.Success = true
    result.EndTime = time.Now()
    return result
}

func (t *MemoryTest) getCgroupMemoryLimit() (uint64, error) {
    // Try to read cgroup memory limit
    data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if err != nil {
        return 0, err
    }

    var limit uint64
    _, err = fmt.Sscanf(string(data), "%d", &limit)
    if err != nil {
        return 0, err
    }

    return limit, nil
}