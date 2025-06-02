package core

import (
	"context"
	"encoding/xml"
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

// NewFrameworkCreate a new testing framework
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

// saveResults saves test results in JUnit XML format
func (f *Framework) saveResults(results []TestResult) error {
	// Create the root element
	testSuites := JUnitTestSuites{}

	// Create a test suite
	testSuite := JUnitTestSuite{
		Name:     "KataContainerTests",
		Tests:    len(results),
		Failures: 0,
		Time:     0,
	}

	// Process each test result
	for _, result := range results {
		// Calculate test duration
		duration := result.EndTime.Sub(result.StartTime)

		// Create test case
		testCase := JUnitTestCase{
			Name:      result.Name,
			ClassName: "KataContainerTest",
			Time:      duration.Seconds(),
		}

		// Store metrics and expected values as properties
		var properties []JUnitProperty

		// Add metrics properties
		for key, value := range result.Metrics {
			properties = append(properties, JUnitProperty{
				Name:  fmt.Sprintf("metric.%s", key),
				Value: fmt.Sprintf("%v", value),
			})
		}

		// Add expected value properties (if any)
		for key, value := range result.ExpectedValues {
			properties = append(properties, JUnitProperty{
				Name:  fmt.Sprintf("expected.%s", key),
				Value: fmt.Sprintf("%v", value),
			})
		}

		// Only add properties if we have any
		if len(properties) > 0 {
			testCase.Properties = JUnitProperties{
				Properties: properties,
			}
		}

		// Add failure information if test failed
		if !result.Success {
			testSuite.Failures++
			testCase.Failure = &JUnitFailure{
				Message: result.Error,
				Type:    "AssertionFailure",
				Value:   fmt.Sprintf("Test failed: %s", result.Error),
			}
		}

		// Add test case to suite
		testSuite.TestCases = append(testSuite.TestCases, testCase)

		// Add to total time
		testSuite.Time += duration.Seconds()
	}

	// Add suite to root element
	testSuites.Suites = append(testSuites.Suites, testSuite)

	// Create the XML file
	filename := fmt.Sprintf("%s/results_%s.xml",
		f.outputDir,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create JUnit XML file: %v", err)
	}
	defer file.Close()

	// Write XML header
	file.WriteString(xml.Header)

	// Create encoder with indentation for readability
	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")

	// Encode and write
	if err := encoder.Encode(testSuites); err != nil {
		return fmt.Errorf("failed to encode JUnit XML: %v", err)
	}

	return nil
}

// getResultString is a helper function to get a human-readable result string
func getResultString(result TestResult) string {
	if result.Success {
		return "PASSED"
	}
	return fmt.Sprintf("FAILED - %s", result.Error)
}
