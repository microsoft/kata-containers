package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kata-containers/tests/kata-containerized-test-tool/internal/core"
	"github.com/kata-containers/tests/kata-containerized-test-tool/internal/tests/sdl"
)

func main() {
	outputDir := flag.String("output", "/results", "Output directory for test results")
	flag.Parse()

	// expect exactly one additional argument: the string of test names
	if flag.NArg() != 1 {
		printUsageAndExit()
	}
	testArg := flag.Arg(0)
	testNames := strings.Fields(testArg)

	if len(testNames) == 0 {
		printUsageAndExit()
	}

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}
	framework := core.NewFramework(*outputDir)

	availableTests := map[string]core.Test{
		"sdl": sdl.New(),
	}
	for _, testName := range testNames {
		test, exists := availableTests[strings.ToLower(testName)]
		if !exists {
			fmt.Printf("Error: Invalid test name '%s'.\n", testName)
			printUsageAndExit()
		}
		fmt.Printf("Running '%s' test\n", testName)
		framework.AddTest(test)
	}

	// run selected tests
	ctx := context.Background()
	if err := framework.RunAll(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Test execution failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Selected tests completed successfully")
}

func printUsageAndExit() {
	fmt.Println("Usage: kata-containerized-test-tool \"<test1> <test2> ...\"")
	fmt.Println("Available tests: cpu, memory, sdl")
	fmt.Println("Example: kata-containerized-test-tool \"cpu memory\"")
	os.Exit(1)
}
