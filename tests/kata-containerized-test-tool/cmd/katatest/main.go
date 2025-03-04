package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

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

	// Create the framework
	framework := core.NewFramework(*outputDir)

	// Register all available tests
	framework.RegisterTest(cpu.New())
	framework.RegisterTest(memory.New())

	// Get tests to run from environment
	testsToRun := getTestsToRun(framework.GetAvailableTests())

	// Run selected tests
	ctx := context.Background()
	results, err := framework.RunTests(ctx, testsToRun, getExpectedValues)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running tests: %v\n", err)
	}

	// Exit with error if any test failed
	for _, result := range results {
		if !result.Success {
			os.Exit(1)
		}
	}
}

// getTestsToRun determines which tests to execute based on environment variables
func getTestsToRun(availableTests map[string]core.Test) []core.Test {
	testsToRun := []core.Test{}

	// Check ENABLED_TESTS environment variable
	enabledTestsEnv := os.Getenv("ENABLED_TESTS")
	if enabledTestsEnv == "" {
		// If not specified, run all tests
		for _, test := range availableTests {
			testsToRun = append(testsToRun, test)
		}
		return testsToRun
	}

	// Parse enabled tests
	enabledTests := strings.Split(enabledTestsEnv, ",")
	for _, testName := range enabledTests {
		testName = strings.TrimSpace(testName)
		if test, exists := availableTests[testName]; exists {
			testsToRun = append(testsToRun, test)
		}
	}

	return testsToRun
}

// Retrieve the expected values for a specific test from environment variables
func getExpectedValues(testName string) map[string]interface{} {
	expectedValues := map[string]interface{}{}

	// Look for expected values in environment variables
	// Format: TEST_<testname>_<param>=value
	prefix := "TEST_" + strings.ToUpper(testName) + "_"

	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, prefix) {
			continue
		}

		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		paramName := strings.ToLower(strings.TrimPrefix(parts[0], prefix))
		paramValue := parts[1]

		// Try to convert to number if possible
		if value, err := strconv.ParseFloat(paramValue, 64); err == nil {
			expectedValues[paramName] = value
		} else {
			expectedValues[paramName] = paramValue
		}
	}

	return expectedValues
}
