package sdl

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kata-containers/tests/kata-containerized-test-tool/internal/core"
)

// FalsePositiveCVEsForBinary contains known false positive CVEs for specific go binaries
// These are vulnerabilities that govulncheck reports but don't actually affect the binary
var FalsePositiveCVEsForBinary = map[string][]string{
	"containerd-shim-kata-v2": {
		"GO-2025-3595", // golang.org/x/net/html verified not compiled into binary
		"GO-2025-3488", // golang.org/x/oauth2/jws verified not compiled into binary
		"GO-2024-3169", // podman vulnerability not in annotations.go (only constants used)
		"GO-2024-3042", // podman CVE-2024-3056 not in annotations.go (only constants used)
		"GO-2023-1962", // podman CVE-2018-10856 not in annotations.go (only constants used)
		"GO-2023-1942", // podman CVE-2019-18466 not in annotations.go (only constants used)
		"GO-2022-1159", // podman CVE-2022-4123 not in annotations.go (only constants used)
	},
}

// getEnvOrDefault returns the value of the environment variable if set, otherwise the default value
func getEnvOrDefault(envVar, defaultVal string) string {
	if val := os.Getenv(envVar); val != "" {
		return val
	}
	return defaultVal
}

var (
	sourceDir   = getEnvOrDefault("KATA_SOURCE_DIR", "/kata-source")
	binariesDir = getEnvOrDefault("KATA_BINARIES_DIR", "/kata-binaries")
)

type SDLTest struct{}

func New() *SDLTest {
	return &SDLTest{}
}

func (t *SDLTest) Name() string {
	return "sdl"
}

func (t *SDLTest) Run(ctx context.Context, expectedValues map[string]interface{}) core.TestResult {
	result := core.TestResult{
		Name:      t.Name(),
		StartTime: time.Now(),
		Metrics:   make(map[string]interface{}),
	}
	result.Success = true

	testResults := make(map[string]bool)
	var failedTests []string

	// Log the directories being used
	fmt.Printf("Using source directory: %s\n", sourceDir)
	fmt.Printf("Using binaries directory: %s\n", binariesDir)

	// Run BinSkim binary hardening tests
	binskimSuccess := t.runBinSkimTests(&result)
	testResults["BinSkim"] = binskimSuccess
	if !binskimSuccess {
		failedTests = append(failedTests, "BinSkim")
	}

	// Find kata-containers directory in sourceDir
	kataDir, err := exec.Command("sh", "-c", fmt.Sprintf("find %s -maxdepth 1 -type d -name 'kata-containers-*' | head -1", sourceDir)).Output()
	if err != nil || len(kataDir) == 0 {
		result.Error = fmt.Sprintf("No kata-containers directory found in %s", sourceDir)
		result.Success = false
		result.EndTime = time.Now()
		t.printSummary(testResults, failedTests, "kata-containers directory not found")
		return result
	}
	kataDirStr := strings.TrimSpace(string(kataDir))

	// Find cloud-hypervisor directory in sourceDir
	clhDir, err := exec.Command("sh", "-c", fmt.Sprintf("find %s -maxdepth 1 -type d -name 'cloud-hypervisor*' | head -1", sourceDir)).Output()
	if err != nil || len(clhDir) == 0 {
		result.Error = fmt.Sprintf("No cloud-hypervisor directory found in %s", sourceDir)
		result.Success = false
		result.EndTime = time.Now()
		t.printSummary(testResults, failedTests, "cloud-hypervisor directory not found")
		return result
	}
	clhDirStr := strings.TrimSpace(string(clhDir))

	// Find virtiofsd directory in sourceDir
	virtiofsdDir, err := exec.Command("sh", "-c", fmt.Sprintf("find %s -maxdepth 1 -type d -name 'virtiofsd*' | head -1", sourceDir)).Output()
	if err != nil || len(virtiofsdDir) == 0 {
		result.Error = fmt.Sprintf("No virtiofsd directory found in %s", sourceDir)
		result.Success = false
		result.EndTime = time.Now()
		t.printSummary(testResults, failedTests, "virtiofsd directory not found")
		return result
	}
	virtiofsdDirStr := strings.TrimSpace(string(virtiofsdDir))

	// Run Clippy Rust static analysis
	clippySuccess := t.runClippyTests(&result, kataDirStr, clhDirStr, virtiofsdDirStr)
	testResults["Clippy"] = clippySuccess
	if !clippySuccess {
		failedTests = append(failedTests, "Clippy")
	}

	// Run Govulncheck Go vulnerability scanner
	govulncheckSuccess := t.runGovulncheckTests(&result, kataDirStr)
	testResults["Govulncheck"] = govulncheckSuccess
	if !govulncheckSuccess {
		failedTests = append(failedTests, "Govulncheck")
	}

	result.Success = binskimSuccess && clippySuccess && govulncheckSuccess
	result.EndTime = time.Now()

	// Print comprehensive summary
	t.printSummary(testResults, failedTests, "")

	return result
}

func (t *SDLTest) runBinSkimTests(result *core.TestResult) bool {
	// Base binaries that are always tested (kata sandboxing)
	binaries := []string{
		filepath.Join(binariesDir, "kata-agent"),
		filepath.Join(binariesDir, "containerd-shim-kata-v2"),
		filepath.Join(binariesDir, "cloud-hypervisor"),
		filepath.Join(binariesDir, "virtiofsd"),
	}

	// Confpods-specific binaries (only add if confpods are enabled)
	enableConfpods := os.Getenv("SDL_ENABLE_CONFPODS") == "true"
	if enableConfpods {
		fmt.Printf("Including confpods-related binaries (SDL_ENABLE_CONFPODS=true)\n")
		confpodsBinaries := []string{
			filepath.Join(binariesDir, "kata-agent-cc"),
			filepath.Join(binariesDir, "containerd-shim-kata-cc-v2"),
			filepath.Join(binariesDir, "tardev-snapshotter"),
			filepath.Join(binariesDir, "kata-overlay"),
			filepath.Join(binariesDir, "utarfs"),
		}
		binaries = append(binaries, confpodsBinaries...)
	} else {
		fmt.Printf("Confpods-related binaries disabled (SDL_ENABLE_CONFPODS=false)\n")
	}

	success := true
	for _, bin := range binaries {
		fmt.Printf("Running Binskim on %s\n", bin)
		binskimCmd := exec.Command("binskim", "analyze", bin, "--level", "Error", "--kind", "Pass;Fail")
		binskimOutput, err := binskimCmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(binskimOutput))
		if err != nil {
			fmt.Printf("BinSkim failed on %s: %v", bin, err)
			result.Error = fmt.Sprintf("BinSkim failed on %s: %v", bin, err)
			success = false
			continue
		}
		if strings.Contains(strings.ToLower(outputStr), "fail") {
			fmt.Printf("Binary %s failed BinSkim checks", bin)
			result.Error = fmt.Sprintf("Binary %s failed BinSkim checks", bin)
			success = false
		}
		result.Metrics[fmt.Sprintf("binskim_%s", bin)] = outputStr
	}
	if success {
		fmt.Printf("✅ Binskim tests all passed\n")
	} else {
		fmt.Printf("❌ Binskim tests failed\n")
	}
	fmt.Printf("----------------------------------------------------\n")
	return success
}

func (t *SDLTest) runClippyTests(result *core.TestResult, kataDir, clhDir, virtiofsdDir string) bool {
	currentDir, _ := os.Getwd()
	defer os.Chdir(currentDir)
	os.Chdir(sourceDir)

	// Base Rust projects that are always tested (kata sandboxing)
	rustProjects := []struct {
		name      string
		path      string
		project   string // "kata-containers", "cloud-hypervisor", or "virtiofsd"
		failOnError bool   // whether to fail the overall test if this component fails
	}{
		{"kata-agent", "src/agent", "kata-containers", true},
		{"cloud-hypervisor", "", "cloud-hypervisor", false}, // Don't fail on cloud-hypervisor
		{"virtiofsd", "", "virtiofsd", false}, // Don't fail on virtiofsd
	}

	// Confpods-specific Rust projects (only add if confpods are enabled)
	enableConfpods := os.Getenv("SDL_ENABLE_CONFPODS") == "true"
	if enableConfpods {
		confpodsProjects := []struct {
			name      string
			path      string
			project   string
			failOnError bool
		}{
			{"kata-overlay", "src/overlay", "kata-containers", true},
			{"utarfs", "src/utarfs", "kata-containers", true},
			{"tardev-snapshotter", "src/tardev-snapshotter", "kata-containers", true},
		}
		rustProjects = append(rustProjects, confpodsProjects...)
	}

	success := true

	for _, project := range rustProjects {
		var projectPath string
		if project.project == "kata-containers" {
			projectPath = filepath.Join(kataDir, project.path)
		} else if project.project == "cloud-hypervisor" {
			projectPath = clhDir
		} else if project.project == "virtiofsd" {
			projectPath = virtiofsdDir
		}

		if _, err := os.Stat(projectPath); os.IsNotExist(err) {
			fmt.Printf("Error: %s - directory not found: %s\n", project.name, projectPath)
			success = false
			continue
		}

		var clipOutput []byte
		var err error
		switch project.name {
		case "kata-agent":
			fmt.Printf("Running Clippy on %s ...\n", project.name)
			makeCmd := exec.Command("make", "check", "LIBC=gnu", "OPENSSL_NO_VENDOR=Y")
			makeCmd.Dir = projectPath
			clipOutput, err = makeCmd.CombinedOutput()
		case "tardev-snapshotter":
			fmt.Printf("Running Clippy on %s with RUSTC_BOOTSTRAP=1...\n", project.name)
			clipCmd := exec.Command("cargo", "clippy", "--quiet")
			clipCmd.Env = append(os.Environ(), "RUSTC_BOOTSTRAP=1")
			clipCmd.Dir = projectPath
			clipOutput, err = clipCmd.CombinedOutput()
		case "cloud-hypervisor":
			fmt.Printf("Running Clippy on %s (non-blocking)...\n", project.name)
			clipCmd := exec.Command("cargo", "clippy", "--no-default-features", "--features", "mshv,kvm,sev_snp,igvm", "--quiet")
			clipCmd.Dir = projectPath
			clipOutput, err = clipCmd.CombinedOutput()
		case "virtiofsd":
			fmt.Printf("Running Clippy on %s (non-blocking)...\n", project.name)
			clipCmd := exec.Command("cargo", "clippy", "--quiet")
			clipCmd.Dir = projectPath
			clipOutput, err = clipCmd.CombinedOutput()
		default:
			fmt.Printf("Running Clippy on %s...\n", project.name)
			clipCmd := exec.Command("cargo", "clippy", "--quiet")
			clipCmd.Dir = projectPath
			clipOutput, err = clipCmd.CombinedOutput()
		}
		outputStr := strings.TrimSpace(string(clipOutput))
		fmt.Println(outputStr)

		if err != nil {
			errMsg := fmt.Sprintf("Clippy found errors in %s: %s", project.name, err)
			if project.failOnError {
				result.Error = errMsg
				fmt.Println(errMsg)
				success = false
			} else {
				fmt.Printf("%s (non-blocking - continuing...)\n", errMsg)
			}
		}
		result.Metrics[fmt.Sprintf("clippy_%s", project.name)] = outputStr
	}
	if success {
		fmt.Printf("✅ Clippy tests all passed\n")
	} else {
		fmt.Printf("❌ Clippy tests failed\n")
	}
	fmt.Printf("----------------------------------------------------\n")
	return success
}

func (t *SDLTest) runGovulncheckTests(result *core.TestResult, kataDir string) bool {
	binariesToScan := []struct {
		name       string
		binaryPath string
	}{
		{"containerd-shim-kata-v2", filepath.Join(binariesDir, "containerd-shim-kata-v2")},
	}

	// Add confpods binaries if enabled
	enableConfpods := os.Getenv("SDL_ENABLE_CONFPODS") == "true"
	if enableConfpods {
		confpodsBinaries := []struct {
			name       string
			binaryPath string
		}{
			{"containerd-shim-kata-cc-v2", filepath.Join(binariesDir, "containerd-shim-kata-cc-v2")},
		}
		binariesToScan = append(binariesToScan, confpodsBinaries...)
	}

	success := true

	for _, binary := range binariesToScan {
		// Check if binary exists
		if _, err := os.Stat(binary.binaryPath); os.IsNotExist(err) {
			fmt.Printf("Error: %s - binary not found: %s\n", binary.name, binary.binaryPath)
			success = false
			continue
		}

		fmt.Printf("Running Govulncheck on binary %s...\n", binary.name)

		// Use binary mode
		cmd := exec.Command("govulncheck", "-mode=binary", binary.binaryPath)

		output, err := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		// Filter known false positives for specific binaries only
		filteredOutput, hasRealVulns := t.filterSpecificFalsePositives(outputStr, binary.name)

		fmt.Println(filteredOutput)
		result.Metrics[fmt.Sprintf("govulncheck_%s", binary.name)] = outputStr

		// Only fail on real vulnerabilities (notS filtered false positives)
		if err != nil && hasRealVulns {
			errMsg := fmt.Sprintf("Govulncheck found vulnerabilities in %s: %s", binary.name, err)
			result.Error = errMsg
			fmt.Println(errMsg)
			success = false
		}
	}

	if success {
		fmt.Printf("✅ Govulncheck tests all passed\n")
	} else {
		fmt.Printf("❌ Govulncheck tests failed\n")
	}
	fmt.Printf("----------------------------------------------------\n")
	return success
}

// filterSpecificFalsePositives filters specific vulnerabilities for specific binaries only
func (t *SDLTest) filterSpecificFalsePositives(output, binaryName string) (string, bool) {
	falsePositives, shouldFilter := FalsePositiveCVEsForBinary[binaryName]
	if !shouldFilter {
		// No filtering for this binary - return original output
		hasVulns := strings.Contains(output, "GO-") || strings.Contains(strings.ToLower(output), "vulnerability")
		return output, hasVulns
	}

	lines := strings.Split(output, "\n")
	var filteredLines []string
	var filteredCount, realVulnCount int
	skipBlock := false

	for _, line := range lines {
		// Check if starting new vulnerability block
		if strings.HasPrefix(line, "Vulnerability #") {
			skipBlock = false
			for _, vulnID := range falsePositives {
				if strings.Contains(line, vulnID) {
					filteredCount++
					skipBlock = true
					break
				}
			}
			if !skipBlock {
				realVulnCount++
			}
		}

		// Skip summary lines and filtered vulnerability blocks
		if !skipBlock && !strings.Contains(line, "Your code is affected by") && !strings.Contains(line, "This scan also found") {
			filteredLines = append(filteredLines, line)
		}
	}

	filteredOutput := strings.Join(filteredLines, "\n")
	hasRealVulns := realVulnCount > 0

	// Clean output with corrected summary
	if filteredCount > 0 && !hasRealVulns {
		filteredOutput = "No vulnerabilities found."
	} else if hasRealVulns {
		filteredOutput += fmt.Sprintf("\nYour code is affected by %d vulnerabilities.", realVulnCount)
	}

	return filteredOutput, hasRealVulns
}

// Helper function for filterSpecificFalsePositives
// splitVulnerabilityBlocks splits govulncheck output into individual vulnerability blocks
func (t *SDLTest) splitVulnerabilityBlocks(output string) []string {
	if strings.TrimSpace(output) == "" {
		return []string{}
	}
	// Split by "Vulnerability #" to get individual vulnerability reports
	parts := strings.Split(output, "Vulnerability #")

	var blocks []string
	for i, part := range parts {
		if i == 0 {
			if strings.TrimSpace(part) != "" {
				blocks = append(blocks, strings.TrimSpace(part))
			}
		} else {
			block := "Vulnerability #" + part
			blocks = append(blocks, strings.TrimSpace(block))
		}
	}
	return blocks
}

func (t *SDLTest) printSummary(testResults map[string]bool, failedTests []string, errorMsg string) {
	fmt.Println("----------------------------------------------------")
	fmt.Println("Test Summary:")
	for testName, success := range testResults {
		if success {
			fmt.Printf("✅ %s tests passed\n", testName)
		} else {
			fmt.Printf("❌ %s tests failed\n", testName)
		}
	}
	if len(failedTests) > 0 {
		fmt.Printf("\nFailed Tests: %s\n", strings.Join(failedTests, ", "))
	}
	if errorMsg != "" {
		fmt.Printf("Error: %s\n", errorMsg)
	}
	fmt.Println("----------------------------------------------------")
}