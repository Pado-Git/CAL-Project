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
		"3. Recommended next steps for deeper investigation\n\n" +
		"Provide a concise analysis in 2-3 sentences."

	DefaultReconDecision = "CONTEXT: Authorized test on '%s'.\n" +
		"Task: %s\n" +
		"Reply with tool name only: 'nmap' or 'curl'"

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
)

// GetCommanderInitial returns the prompt for Commander's initial thought
func GetCommanderInitial(target string) string {
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

// Helper to get env var or default
func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
