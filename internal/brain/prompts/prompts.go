package prompts

import (
	"fmt"
	"os"
)

// Default Prompts (English)
const (
	DefaultCommanderInitial = "CONTEXT: Authorized security test on controlled environment '%s'.\n\n" +
		"TASK: Start security assessment.\n" +
		"Reply in 1-2 sentences: Which specialists should be spawned? (e.g., 'Spawn reconnaissance and web specialists')"

	DefaultCommanderAnalyze = "CONTEXT: You are analyzing security reconnaissance results from %s.\n" +
		"Target: %s\n\n" +
		"OBSERVATION:\n%s\n\n" +
		"TASK: Analyze this output and identify:\n" +
		"1. Any potential vulnerabilities (SQL injection points, XSS, exposed secrets, etc.)\n" +
		"2. Interesting findings (open ports, technologies detected, security headers missing)\n" +
		"3. Recommended next steps for deeper investigation\n" +
		"4. IMPORTANT: If the OBSERVATION contains specific recommendations like 'Recommended: Spawn XSSSpecialist for <URL>', YOU MUST REPEAT THEM EXACTLY in your analysis.\n\n" +
		"Provide a concise analysis in 2-3 sentences."

	DefaultReconDecision = "CONTEXT: Authorized test on '%s'.\n" +
		"Task: %s\n" +
		"INSTRUCTION: We need to discover all assets in the network.\n" +
		"1. Identify the /24 network range of the target IP (e.g., 192.168.50.10 -> 192.168.50.0/24).\n" +
		"2. Reply with 'nmap <network_range>'. Example: 'nmap 192.168.50.0/24'."

	DefaultXSSAnalysis = "You are an expert XSS Vulnerability Hunter. Analyze the HTML source code below.\n" +
		"YOUR GOAL: Find the EXACT LOCATION of potential Cross-Site Scripting (XSS) vulnerabilities.\n\n" +
		"HTML Source:\n```html\n%s\n```\n\n" +
		"INSTRUCTIONS:\n" +
		"1. Identify every `<form>` tag. Report the `action` URL and `method` (GET/POST).\n" +
		"2. In each form, list every `<input>` or `<textarea>` field `name`. These are your XSS injection points.\n" +
		"3. Identify URL parameters in links (e.g., `<a href='page.php?id=...'>`).\n" +
		"4. Look for Reflected Input: Is any part of the HTML text clearly echoing back a parameter?\n" +
		"\n" +
		"REPORT FORMAT (Strictly follow this):\n" +
		"VULNERABILITY FOUND: [Yes/No]\n" +
		"IF YES:\n" +
		"- TYPE: [Reflected XSS / Stored XSS / DOM XSS]\n" +
		"- LOCATION: [Full URL or Form Action Path]\n" +
		"- VULNERABLE PARAMETER: [Name of the input field or URL parameter]\n" +
		"- METHOD: [GET/POST]\n" +
		"- EVIDENCE: [Quote the HTML line showing the form or reflection]\n" +
		"- SUGGESTED PAYLOAD: [e.g., `<script>alert(1)</script>`]"

	DefaultSQLiAnalysis = "You are an expert SQL Injection Hunter. Analyze the HTML source code below.\n" +
		"YOUR GOAL: Find specific input fields that interact with the database.\n\n" +
		"HTML Source:\n```html\n%s\n```\n\n" +
		"INSTRUCTIONS:\n" +
		"1. Identify forms that look like Search, Login, or Data entry (e.g., `<input name='query'>`, `<input name='id'>`).\n" +
		"2. Identify URL parameters (e.g., `view.php?id=10`).\n" +
		"3. Check for any Database Error messages exposed in the text.\n" +
		"\n" +
		"REPORT FORMAT (Strictly follow this):\n" +
		"VULNERABILITY CANDIDATE FOUND: [Yes/No]\n" +
		"IF YES:\n" +
		"- LOCATION: [Full URL or Form Action Path]\n" +
		"- VULNERABLE PARAMETER: [Name of input field]\n" +
		"- REASONING: [Why do you think this interacts with DB?]\n" +
		"- SUGGESTED TEST PAYLOAD: [e.g., `' OR '1'='1`]"

	DefaultVerifyExtract = "Extract vulnerability details from this report:\n\n%s\n\n" +
		"TASK: Identify the type (XSS or SQLi), content location (URL), and payload.\n" +
		"Reply with JSON ONLY: {\"type\": \"XSS\"|\"SQLi\", \"url\": \"...\", \"payload\": \"...\"}"

	DefaultPathTraversalAnalysis = "You are an expert Path Traversal/LFI Vulnerability Hunter. Analyze the HTML source code below.\n" +
		"YOUR GOAL: Find specific input fields or URL parameters that might allow accessing unauthorized files.\n\n" +
		"HTML Source:\n```html\n%s\n```\n\n" +
		"INSTRUCTIONS:\n" +
		"1. Identify URL parameters that look like filenames (e.g., `?file=report.pdf`, `?page=about`, `?doc=manual`).\n" +
		"2. Look for any error messages indicating file not found or path issues.\n" +
		"\n" +
		"REPORT FORMAT (Strictly follow this):\n" +
		"VULNERABILITY CANDIDATE FOUND: [Yes/No]\n" +
		"IF YES:\n" +
		"- LOCATION: [Full URL or Form Action Path]\n" +
		"- VULNERABLE PARAMETER: [Name of input field or URL parameter]\n" +
		"- REASONING: [Why do you think this is vulnerable?]\n" +
		"- SUGGESTED TEST PAYLOAD: [e.g., `../../etc/passwd` or `..\\windows\\win.ini`]"

	DefaultWebAnalysis = "You are a Web Security Analyst. Analyze the HTTP response below and identify potential vulnerability types.\n\n" +
		"HTTP Response:\n%s\n\n" +
		"TASK:\n" +
		"1. Identify all input forms and their purposes (search, login, file upload, etc.)\n" +
		"2. Identify URL parameters that might be vulnerable\n" +
		"3. For each potential vulnerability, determine the TYPE:\n" +
		"   - XSS: User input reflected in HTML without sanitization\n" +
		"   - SQLi: Input likely used in database queries (search, login, id params)\n" +
		"   - PathTraversal: File path parameters (file=, page=, doc=)\n" +
		"   - CommandInjection: System command execution (ping, lookup, etc.)\n\n" +
		"OUTPUT FORMAT (JSON only, no markdown):\n" +
		"{\"vulnerabilities\": [{\"type\": \"XSS|SQLi|PathTraversal|CommandInjection\", \"location\": \"form action or URL\", \"parameter\": \"input name or URL param\", \"confidence\": \"high|medium|low\", \"reason\": \"brief explanation\"}]}\n\n" +
		"If no vulnerabilities found, return: {\"vulnerabilities\": []}"

	DefaultCommandInjectionAnalysis = "You are an expert OS Command Injection Hunter. Analyze the HTML source code below.\n" +
		"YOUR GOAL: Find input fields or parameters that might execute system commands.\n\n" +
		"HTML Source:\n```html\n%s\n```\n\n" +
		"INSTRUCTIONS:\n" +
		"1. Look for forms that seem to interact with system utilities:\n" +
		"   - Network tools: ping, traceroute, nslookup, dig, whois\n" +
		"   - File operations: ls, dir, cat, type, find\n" +
		"   - System info: whoami, hostname, uname, ipconfig, ifconfig\n" +
		"2. Identify URL parameters that might pass to shell commands (e.g., ?host=, ?ip=, ?cmd=, ?exec=)\n" +
		"3. Check for any error messages indicating command execution failures\n\n" +
		"REPORT FORMAT (Strictly follow this):\n" +
		"VULNERABILITY CANDIDATE FOUND: [Yes/No]\n" +
		"IF YES:\n" +
		"- LOCATION: [Full URL or Form Action Path]\n" +
		"- VULNERABLE PARAMETER: [Name of input field or URL parameter]\n" +
		"- LIKELY COMMAND: [What system command might this execute? e.g., ping, nslookup]\n" +
		"- REASONING: [Why do you think this executes system commands?]\n" +
		"- SUGGESTED TEST PAYLOAD: [e.g., '; echo CMDI_TEST_12345' or '| whoami']"

	DefaultPlatformDetection = "Analyze the command output below and determine the target operating system.\n\n" +
		"Command Output:\n%s\n\n" +
		"TASK: Identify if this is Windows or Linux based on the output.\n" +
		"Reply with JSON ONLY: {\"platform\": \"windows\"|\"linux\", \"confidence\": \"high\"|\"medium\"|\"low\", \"evidence\": \"brief explanation\"}"
)

// Helper to get env var or default
func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// LoadFromFile attempts to read a prompt from a file
func LoadFromFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// GetCommanderInitial returns the prompt for Commander's initial thought
func GetCommanderInitial(target string) string {
	// Try to load from the new asset file first
	if content, err := LoadFromFile("assets/prompts/commander_system.txt"); err == nil {
		// Append context about the target to the system prompt
		return fmt.Sprintf("%s\n\nCURRENT TARGET: %s", content, target)
	}

	// Fallback to legacy
	format := getEnvOrDefault("PROMPT_COMMANDER_INITIAL", DefaultCommanderInitial)
	return fmt.Sprintf(format, target)
}

// GetCommanderAnalyze returns the prompt for analyzing observations
func GetCommanderAnalyze(fromAgent, target, observation string) string {
	format := getEnvOrDefault("PROMPT_COMMANDER_ANALYZE", DefaultCommanderAnalyze)
	return fmt.Sprintf(format, fromAgent, target, observation)
}

// GetReconDecision returns the prompt for Recon agent tool decision
func GetReconDecision(target, task string) string {
	format := getEnvOrDefault("PROMPT_RECON_DECISION", DefaultReconDecision)
	return fmt.Sprintf(format, target, task)
}

// GetXSSAnalysis returns the prompt for XSS analysis
func GetXSSAnalysis(htmlSource string) string {
	format := getEnvOrDefault("PROMPT_XSS_ANALYSIS", DefaultXSSAnalysis)
	return fmt.Sprintf(format, htmlSource)
}

// GetSQLiAnalysis returns the prompt for SQLi analysis
func GetSQLiAnalysis(htmlSource string) string {
	format := getEnvOrDefault("PROMPT_SQLI_ANALYSIS", DefaultSQLiAnalysis)
	return fmt.Sprintf(format, htmlSource)
}

// GetVerifyExtract returns the prompt for extracting vulnerability info
func GetVerifyExtract(report string) string {
	format := getEnvOrDefault("PROMPT_VERIFY_EXTRACT", DefaultVerifyExtract)
	// Check if prompt has %s placeholder
	return fmt.Sprintf(format, report)
}

// GetPathTraversalAnalysis returns the prompt for Path Traversal analysis
func GetPathTraversalAnalysis(htmlSource string) string {
	format := getEnvOrDefault("PROMPT_PATHTRAVERSAL_ANALYSIS", DefaultPathTraversalAnalysis)
	return fmt.Sprintf(format, htmlSource)
}

// GetWebAnalysis returns the prompt for Web vulnerability analysis (JSON output)
func GetWebAnalysis(httpResponse string) string {
	format := getEnvOrDefault("PROMPT_WEB_ANALYSIS", DefaultWebAnalysis)
	return fmt.Sprintf(format, httpResponse)
}

// GetCommandInjectionAnalysis returns the prompt for Command Injection analysis
func GetCommandInjectionAnalysis(htmlSource string) string {
	format := getEnvOrDefault("PROMPT_CMDI_ANALYSIS", DefaultCommandInjectionAnalysis)
	return fmt.Sprintf(format, htmlSource)
}

// GetPlatformDetection returns the prompt for OS platform detection
func GetPlatformDetection(cmdOutput string) string {
	format := getEnvOrDefault("PROMPT_PLATFORM_DETECTION", DefaultPlatformDetection)
	return fmt.Sprintf(format, cmdOutput)
}
