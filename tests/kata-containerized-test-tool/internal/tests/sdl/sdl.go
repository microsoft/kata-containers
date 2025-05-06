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
	return "SDL & Binary Hardening Test"
}

func (t *SDLTest) Run(ctx context.Context) core.TestResult {
	result := core.TestResult{
		Name:      t.Name(),
		StartTime: time.Now(),
		Metrics:   make(map[string]interface{}),
	}
	result.Success = true

	// Log the directories being used
	fmt.Printf("Using source directory: %s\n", sourceDir)
	fmt.Printf("Using binaries directory: %s\n", binariesDir)

	// Run BinSkim binary hardening tests
	binskimSuccess := t.runBinSkimTests(&result)

	// Find kata-containers directory in sourceDir
	kataDir, err := exec.Command("sh", "-c", fmt.Sprintf("find %s -maxdepth 1 -type d -name 'kata-containers-*' | head -1", sourceDir)).Output()
	if err != nil || len(kataDir) == 0 {
		result.Error = fmt.Sprintf("No kata-containers directory found in %s", sourceDir)
		result.Success = false
		result.EndTime = time.Now()
		return result
	}
	kataDirStr := strings.TrimSpace(string(kataDir))

	// Find cloud-hypervisor directory in sourceDir
	clhDir, err := exec.Command("sh", "-c", fmt.Sprintf("find %s -maxdepth 1 -type d -name 'cloud-hypervisor*' | head -1", sourceDir)).Output()
	if err != nil || len(clhDir) == 0 {
		result.Error = fmt.Sprintf("No cloud-hypervisor directory found in %s", sourceDir)
		result.Success = false
		result.EndTime = time.Now()
		return result
	}
	clhDirStr := strings.TrimSpace(string(clhDir))

	// Find virtiofsd directory in sourceDir
	virtiofsdDir, err := exec.Command("sh", "-c", fmt.Sprintf("find %s -maxdepth 1 -type d -name 'virtiofsd*' | head -1", sourceDir)).Output()
	if err != nil || len(virtiofsdDir) == 0 {
		result.Error = fmt.Sprintf("No virtiofsd directory found in %s", sourceDir)
		result.Success = false
		result.EndTime = time.Now()
		return result
	}
	virtiofsdDirStr := strings.TrimSpace(string(virtiofsdDir))

	// Run Clippy Rust static analysis
	clippySuccess := t.runClippyTests(&result, kataDirStr, clhDirStr, virtiofsdDirStr)

	// Run Nancy Go dependency security check
	nancySuccess := t.runNancyTests(&result, kataDirStr)

	// Run Govulncheck Go vulnerability scanner
	govulncheckSuccess := t.runGovulncheckTests(&result, kataDirStr)

	result.Success = binskimSuccess && clippySuccess && nancySuccess && govulncheckSuccess
	result.EndTime = time.Now()
	return result
}

func (t *SDLTest) runBinSkimTests(result *core.TestResult) bool {
	binaries := []string{
		filepath.Join(binariesDir, "kata-agent"),
		filepath.Join(binariesDir, "kata-agent-cc"),
		filepath.Join(binariesDir, "containerd-shim-kata-v2"),
		filepath.Join(binariesDir, "containerd-shim-kata-cc-v2"),
		filepath.Join(binariesDir, "tardev-snapshotter"),
		filepath.Join(binariesDir, "kata-overlay"),
		filepath.Join(binariesDir, "utarfs"),
		filepath.Join(binariesDir, "cloud-hypervisor"),
		filepath.Join(binariesDir, "virtio-fsd"),
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

	rustProjects := []struct {
		name    string
		path    string
		project string // "kata-containers", "cloud-hypervisor", or "virtiofsd"
	}{
		{"kata-agent", "src/agent", "kata-containers"},
		{"kata-overlay", "src/overlay", "kata-containers"},
		{"utarfs", "src/utarfs", "kata-containers"},
		{"tardev-snapshotter", "src/tardev-snapshotter", "kata-containers"},
		{"cloud-hypervisor", "", "cloud-hypervisor"},
		{"virtiofsd", "", "virtiofsd"}, // Added virtiofsd
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
			// Use the Makefile for agent
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
			fmt.Printf("Running Clippy on %s...\n", project.name)
			clipCmd := exec.Command("cargo", "clippy", "--no-default-features", "--features", "mshv,kvm,sev_snp,igvm", "--quiet")
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
			result.Error = errMsg
			fmt.Println(errMsg)
			success = false
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

func (t *SDLTest) runNancyTests(result *core.TestResult, kataDir string) bool {
	goProjects := []struct {
		name string
		path string
	}{
		{"kata-runtime", "src/runtime"},
	}
	success := true

	for _, project := range goProjects {
		projectPath := filepath.Join(kataDir, project.path)
		if _, err := os.Stat(projectPath); os.IsNotExist(err) {
			fmt.Printf("Error: %s - directory not found: %s\n", project.name, projectPath)
			success = false
			continue
		}

		fmt.Printf("Running Nancy on %s...\n", project.name)
		cmd := exec.Command("sh", "-c", "go list -mod=mod -m all | nancy sleuth")
		cmd.Dir = projectPath

		output, err := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		fmt.Println(outputStr)
		result.Metrics[fmt.Sprintf("nancy_%s", project.name)] = outputStr
		if err != nil {
			errMsg := fmt.Sprintf("Nancy found vulnerabilities in %s: %s", project.name, err)
			result.Error = errMsg
			fmt.Println(errMsg)
			success = false
		}
	}
	if success {
		fmt.Printf("✅ Nancy tests all passed\n")
	} else {
		fmt.Printf("❌ Nancy tests failed\n")
	}
	fmt.Printf("----------------------------------------------------\n")
	return success
}

func (t *SDLTest) runGovulncheckTests(result *core.TestResult, kataDir string) bool {
	goProjects := []struct {
		name string
		path string
	}{
		{"kata-runtime", "src/runtime"},
	}
	success := true

	for _, project := range goProjects {
		projectPath := filepath.Join(kataDir, project.path)
		if _, err := os.Stat(projectPath); os.IsNotExist(err) {
			fmt.Printf("Error: %s - directory not found: %s\n", project.name, projectPath)
			success = false
			continue
		}

		fmt.Printf("Running Govulncheck on %s...\n", project.name)

		// generate required configuration files
		generateCmd := exec.Command("make", "generate-config", "pkg/katautils/config-settings.go")
		generateCmd.Dir = projectPath
		generateOutput, err := generateCmd.CombinedOutput()
		if err != nil {
			errMsg := fmt.Sprintf("Failed to generate config files for %s: %s\n%s",
				project.name, err, string(generateOutput))
			result.Error = errMsg
			fmt.Println(errMsg)
			return false
		}

		cmd := exec.Command("govulncheck", "./...")
		cmd.Dir = projectPath

		output, err := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		fmt.Println(outputStr)
		result.Metrics[fmt.Sprintf("govulncheck_%s", project.name)] = outputStr
		if err != nil {
			errMsg := fmt.Sprintf("Govulncheck found vulnerabilities in %s: %s", project.name, err)
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
