package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Framework handles test registration, configuration, and execution
type Framework struct {
	tests     map[string]Test
	outputDir string
}

// NewFramework creates a new testing framework
func NewFramework(outputDir string) *Framework {
	return &Framework{
		tests:     make(map[string]Test),
		outputDir: outputDir,
	}
}

// RegisterTest adds a test to the framework
func (f *Framework) RegisterTest(test Test) {
	f.tests[test.Name()] = test
}

// GetAvailableTests returns all registered tests
func (f *Framework) GetAvailableTests() map[string]Test {
	return f.tests
}

// ValidateConfiguration checks if the provided test configurations are valid
func (f *Framework) ValidateConfiguration(testsToRun []Test,
	getExpectedValuesFunc func(string) map[string]interface{}) []string {

	warnings := []string{}

	// Check for enabled tests with no matching registered test
	enabledTestsEnv := os.Getenv("ENABLED_TESTS")
	if enabledTestsEnv != "" {
		enabledTests := strings.Split(enabledTestsEnv, ",")
		for _, testName := range enabledTests {
			testName = strings.TrimSpace(testName)
			if _, exists := f.tests[testName]; !exists {
				warnings = append(warnings, fmt.Sprintf("Warning: Test '%s' is enabled but not registered", testName))
			}
		}
	}

	// Create a map of tests being run for quick lookup
	runningTests := make(map[string]bool)
	for _, test := range testsToRun {
		runningTests[test.Name()] = true
	}

	// Check for test parameters for tests that aren't being run
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "TEST_") {
			continue
		}

		parts := strings.SplitN(env, "_", 3)
		if len(parts) < 3 {
			continue
		}

		testName := strings.ToLower(parts[1])

		// Skip if this is a running test
		if runningTests[testName] {
			continue
		}

		// This is a parameter for a test that isn't running
		warnings = append(warnings, fmt.Sprintf(
			"Warning: Environment variable '%s' is set but test '%s' is not enabled",
			strings.SplitN(env, "=", 2)[0], testName))
	}

	return warnings
}

// RunTest executes a single test with the given expected values
func (f *Framework) RunTest(ctx context.Context, test Test, expectedValues map[string]interface{}) TestResult {
	return test.Run(ctx, expectedValues)
}

// RunTests executes the given tests with their expected values
func (f *Framework) RunTests(ctx context.Context, testsToRun []Test,
	getExpectedValuesFunc func(string) map[string]interface{}) ([]TestResult, error) {

	results := make([]TestResult, 0, len(testsToRun))

	for _, test := range testsToRun {
		expectedValues := getExpectedValuesFunc(test.Name())
		result := test.Run(ctx, expectedValues)
		results = append(results, result)

		// Print test result to stdout
		fmt.Printf("Test %s: %s\n", test.Name(), getResultString(result))
	}

	// Save results to file
	if err := f.saveResults(results); err != nil {
		return results, fmt.Errorf("failed to save results: %v", err)
	}

	return results, nil
}

// SaveResults writes test results to a JSON file
func (f *Framework) saveResults(results []TestResult) error {
	filename := fmt.Sprintf("%s/results_%s.json",
		f.outputDir,
		time.Now().Format("20060102_150405"))

	data, err := json.MarshalIndent(results, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// Helper function to get a human-readable result string
func getResultString(result TestResult) string {
	if result.Success {
		return "PASSED"
	}
	return fmt.Sprintf("FAILED - %s", result.Error)
}
