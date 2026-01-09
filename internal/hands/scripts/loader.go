package scripts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Loader loads and processes script templates from assets/scripts
type Loader struct {
	scriptsDir string
}

// NewLoader creates a new script loader
// If scriptsDir is empty, it will try to find the assets/scripts directory
func NewLoader(scriptsDir string) *Loader {
	if scriptsDir == "" {
		// Try to find assets/scripts relative to executable or working directory
		candidates := []string{
			"assets/scripts",
			"../assets/scripts",
			"../../assets/scripts",
			"cal-project/assets/scripts",
		}

		// Also try relative to executable
		if execPath, err := os.Executable(); err == nil {
			execDir := filepath.Dir(execPath)
			candidates = append(candidates,
				filepath.Join(execDir, "assets", "scripts"),
				filepath.Join(execDir, "..", "assets", "scripts"),
				filepath.Join(execDir, "..", "..", "assets", "scripts"),
			)
		}

		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				scriptsDir = candidate
				break
			}
		}
	}

	return &Loader{
		scriptsDir: scriptsDir,
	}
}

// LoadScript loads a script by name and substitutes variables
func (l *Loader) LoadScript(name string, vars map[string]string) (string, error) {
	if l.scriptsDir == "" {
		return "", fmt.Errorf("scripts directory not found")
	}

	path := filepath.Join(l.scriptsDir, name)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to load script %s: %w", name, err)
	}

	script := string(content)

	// Substitute variables ({{VAR_NAME}} format)
	for key, value := range vars {
		placeholder := "{{" + key + "}}"
		script = strings.ReplaceAll(script, placeholder, value)
	}

	return script, nil
}

// GetDeployAgentScript returns the agent deployment script for the specified platform
func (l *Loader) GetDeployAgentScript(platform, agentURL, agentPath string) (string, error) {
	var scriptName string
	switch strings.ToLower(platform) {
	case "windows":
		scriptName = "deploy_agent_windows.ps1"
	case "linux":
		scriptName = "deploy_agent_linux.sh"
	default:
		return "", fmt.Errorf("unsupported platform: %s", platform)
	}

	vars := map[string]string{
		"AGENT_URL":  agentURL,
		"AGENT_PATH": agentPath,
	}

	return l.LoadScript(scriptName, vars)
}

// GetExecutorForPlatform returns the appropriate executor name for the platform
func GetExecutorForPlatform(platform string) string {
	switch strings.ToLower(platform) {
	case "windows":
		return "powershell"
	case "linux":
		return "bash"
	default:
		return "bash"
	}
}

// GetDefaultAgentPath returns the default path where the agent should be saved
func GetDefaultAgentPath(platform string) string {
	switch strings.ToLower(platform) {
	case "windows":
		return "C:\\Windows\\Temp\\agent.exe"
	case "linux":
		return "/tmp/agent"
	default:
		return "/tmp/agent"
	}
}
