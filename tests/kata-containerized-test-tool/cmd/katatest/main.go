package main

import (
    "context"
    "flag"
    "fmt"
    "os"
    
    "github.com/kata-containers/tests/kata-containerized-test-tool/internal/core"
    "github.com/kata-containers/tests/kata-containerized-test-tool/internal/tests/cpu"
    "github.com/kata-containers/tests/kata-containerized-test-tool/internal/tests/memory"
)

func main() {
    outputDir := flag.String("output", "results", "Output directory for test results")
    flag.Parse()
    
    if err := os.MkdirAll(*outputDir, 0755); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
        os.Exit(1)
    }
    
    framework := core.NewFramework(*outputDir)
    
    // Add CPU test
    framework.AddTest(cpu.New())
    framework.AddTest(memory.New())
    
    // Run all tests
    ctx := context.Background()
    if err := framework.RunAll(ctx); err != nil {
        fmt.Fprintf(os.Stderr, "Test execution failed: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Println("Tests completed successfully")
}