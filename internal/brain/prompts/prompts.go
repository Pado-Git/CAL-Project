package prompts

import (
	"context"
	"fmt"
	"log"
	"os"
)

// Global manager instance (Phase 2: PromptManager with Hot Reload, Cache, Validation)
var (
	manager        *PromptManager
	isInitialized  bool
)

// Initialize initializes the prompt management system
// enableRAG parameter controls whether to use RAG mode (Phase 3 feature)
func Initialize(ctx context.Context, enableRAG bool) error {
	configPath := "assets/prompts/config.yaml"

	// Load configuration
	config, err := LoadConfigFromFile(configPath)
	if err != nil {
		log.Printf("[Prompts] Warning: Failed to load config: %v, using defaults", err)
		// Continue with defaults - LoadConfigFromFile returns default config
	}

	// Apply RAG mode from CLI/ENV parameter (overrides config.yaml)
	config.PromptSystem.RAG.Enabled = enableRAG

	// Phase 2-3: Use full PromptManager with Hot Reload, Cache, Validation, and optional RAG
	manager, err = NewPromptManager(ctx, config)
	if err != nil {
		log.Printf("[Prompts] Failed to create PromptManager: %v", err)
		return err
	}

	isInitialized = true

	// Log the active mode
	if enableRAG {
		log.Printf("[Prompts] RAG mode enabled (Qdrant vector search)")
	} else {
		log.Printf("[Prompts] Direct file loading mode (default)")
	}

	return nil
}

// Close cleans up prompt system resources
func Close() {
	if manager != nil {
		manager.Close()
	}
	isInitialized = false
	manager = nil
}

// getFormattedPrompt is the internal function that loads and formats a prompt
func getFormattedPrompt(promptID string, vars map[string]interface{}) string {
	// If not initialized, fall back to legacy prompts
	if !isInitialized || manager == nil {
		return getLegacyPrompt(promptID, vars)
	}

	// Try to load from PromptManager (with cache, validation, hot reload)
	prompt, err := manager.Get(context.Background(), promptID)
	if err != nil {
		log.Printf("[Prompts] Failed to load prompt %s: %v, using legacy", promptID, err)
		return getLegacyPrompt(promptID, vars)
	}

	// Format the prompt
	formatted, err := Format(prompt, vars)
	if err != nil {
		log.Printf("[Prompts] Failed to format prompt %s: %v, using legacy", promptID, err)
		return getLegacyPrompt(promptID, vars)
	}

	return formatted
}

// getLegacyPrompt returns the hardcoded prompt (fallback)
func getLegacyPrompt(promptID string, vars map[string]interface{}) string {
	// Map promptID to legacy Get* functions
	switch promptID {
	case "initial":
		if target, ok := vars["target"].(string); ok {
			return fmt.Sprintf(DefaultCommanderInitial, target)
		}
	case "analyze":
		fromAgent, _ := vars["from_agent"].(string)
		target, _ := vars["target"].(string)
		observation, _ := vars["observation"].(string)
		return fmt.Sprintf(DefaultCommanderAnalyze, fromAgent, target, observation)
	case "decision":
		target, _ := vars["target"].(string)
		task, _ := vars["task"].(string)
		return fmt.Sprintf(DefaultReconDecision, target, task)
	case "web_analysis":
		if httpResponse, ok := vars["http_response"].(string); ok {
			return fmt.Sprintf(DefaultWebAnalysis, httpResponse)
		}
	case "xss_analysis":
		if htmlSource, ok := vars["html_source"].(string); ok {
			return fmt.Sprintf(DefaultXSSAnalysis, htmlSource)
		}
	case "sqli_analysis":
		if htmlSource, ok := vars["html_source"].(string); ok {
			return fmt.Sprintf(DefaultSQLiAnalysis, htmlSource)
		}
	case "cmdi_analysis":
		if htmlSource, ok := vars["html_source"].(string); ok {
			return fmt.Sprintf(DefaultCommandInjectionAnalysis, htmlSource)
		}
	case "path_traversal":
		if htmlSource, ok := vars["html_source"].(string); ok {
			return fmt.Sprintf(DefaultPathTraversalAnalysis, htmlSource)
		}
	case "file_upload":
		if htmlSource, ok := vars["html_source"].(string); ok {
			return fmt.Sprintf(DefaultFileUploadAnalysis, htmlSource)
		}
	case "crawler":
		htmlContent, _ := vars["html_content"].(string)
		baseURL, _ := vars["base_url"].(string)
		return fmt.Sprintf(DefaultCrawlAnalysis, htmlContent, baseURL)
	case "login_form":
		if htmlContent, ok := vars["html_content"].(string); ok {
			return fmt.Sprintf(DefaultLoginFormAnalysis, htmlContent)
		}
	case "extract":
		if report, ok := vars["report"].(string); ok {
			return fmt.Sprintf(DefaultVerifyExtract, report)
		}
	case "platform_detect":
		if cmdOutput, ok := vars["cmd_output"].(string); ok {
			return fmt.Sprintf(DefaultPlatformDetection, cmdOutput)
		}
	}

	log.Printf("[Prompts] Unknown prompt ID: %s", promptID)
	return fmt.Sprintf("ERROR: Unknown prompt %s", promptID)
}

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
		"   - CommandInjection: System command execution (ping, lookup, etc.)\n" +
		"   - FileUpload: File upload forms (input type=\"file\") without proper validation\n\n" +
		"OUTPUT FORMAT (JSON only, no markdown):\n" +
		"{\"vulnerabilities\": [{\"type\": \"XSS|SQLi|PathTraversal|CommandInjection|FileUpload\", \"location\": \"form action or URL\", \"parameter\": \"input name or URL param\", \"confidence\": \"high|medium|low\", \"reason\": \"brief explanation\"}]}\n\n" +
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

	DefaultFileUploadAnalysis = "You are an expert File Upload Vulnerability Hunter. Analyze the HTML source code below.\n" +
		"YOUR GOAL: Find input fields that allow file uploads and assess their security.\n\n" +
		"HTML Source:\n```html\n%s\n```\n\n" +
		"INSTRUCTIONS:\n" +
		"1. Identify all `<input type=\"file\">` elements and their containing forms.\n" +
		"2. Look for upload-related endpoints:\n" +
		"   - Common patterns: act/write.php, act/upload.php, /upload, /upload.php, /files/upload\n" +
		"   - Board/forum uploads: write.php, post.php, submit.php\n" +
		"3. Check for file storage hints:\n" +
		"   - Upload directories: /uploads/, /files/, /attachments/, /data/\n" +
		"   - Image paths in HTML that reveal storage location\n" +
		"4. Look for form parameters that suggest file board/gallery:\n" +
		"   - type=freeboard, type=pds, board_type, category\n" +
		"   - title, contents, subject fields alongside file input\n" +
		"5. Check client-side validation (accept attribute, JavaScript).\n\n" +
		"COMMON VULNERABLE PATTERNS:\n" +
		"- PHP bulletin board systems often use 'act/write.php' for uploads\n" +
		"- Files typically stored in '/uploads/' directory\n" +
		"- Lack of extension validation allows .php file upload\n\n" +
		"REPORT FORMAT (Strictly follow this):\n" +
		"VULNERABILITY CANDIDATE FOUND: [Yes/No]\n" +
		"IF YES:\n" +
		"- LOCATION: [Full URL or Form Action Path]\n" +
		"- FILE INPUT NAME: [Name attribute of the file input, e.g., 'upload']\n" +
		"- UPLOAD ENDPOINT: [Where form submits, e.g., 'act/write.php']\n" +
		"- CLIENT-SIDE VALIDATION: [Yes/No - describe any accept attributes or JS validation]\n" +
		"- POTENTIAL UPLOAD PATH: [e.g., '/uploads/' if visible in HTML]\n" +
		"- REASONING: [Why this might be vulnerable - e.g., no extension check, board upload functionality]\n" +
		"- SUGGESTED TEST: [Upload PHP web shell as 'webshell.php' to test execution in /uploads/ directory]"

	DefaultCrawlAnalysis = "You are a web crawler. Extract all links from the HTML below.\n\n" +
		"HTML Content:\n%s\n\n" +
		"Base URL: %s\n\n" +
		"INSTRUCTIONS:\n" +
		"1. Find all <a href=\"...\"> links\n" +
		"2. Find all <form action=\"...\"> endpoints\n" +
		"3. Find JavaScript redirects in <script> tags:\n" +
		"   - window.location.href=\"...\"\n" +
		"   - window.location=\"...\"\n" +
		"   - location.href=\"...\"\n" +
		"   - location=\"...\"\n" +
		"4. Find onclick event handlers with navigation:\n" +
		"   - onclick=\"window.location.href='...'\"\n" +
		"   - onclick=\"location.href='...'\"\n" +
		"   - onclick=\"window.location='...'\"\n" +
		"   - onclick=\"location='...'\"\n" +
		"   EXAMPLE: <button onclick=\"window.location.href='?p=write.php&t=freeboard';\">write</button>\n" +
		"   → Extract: ?p=write.php&t=freeboard\n" +
		"5. Convert relative URLs to absolute URLs using the Base URL\n\n" +
		"OUTPUT FORMAT (JSON only, no markdown, no code blocks):\n" +
		"{\"links\": [\"http://example.com/page1\", \"http://example.com/page2\"]}\n\n" +
		"CRITICAL: Output ONLY raw JSON. Do NOT wrap in ```json or ``` code blocks."

	DefaultLoginFormAnalysis = "You are a login form analyzer. Extract login form details.\n\n" +
		"HTML Content:\n%s\n\n" +
		"INSTRUCTIONS:\n" +
		"1. Find <form> with <input type=\"password\">\n" +
		"2. Extract form's action attribute\n" +
		"3. Extract method (GET/POST)\n" +
		"4. Extract EXACT field names from HTML:\n" +
		"   - Find the <input> for username/email (look for name=\"email\" or name=\"username\")\n" +
		"   - Find the <input type=\"password\"> (look for name=\"password\" or name=\"pass\")\n" +
		"5. Return the ACTUAL field names from the HTML, not mapped names\n\n" +
		"EXAMPLES:\n" +
		"If HTML has: <input name=\"email\"> and <input name=\"password\" type=\"password\">\n" +
		"Return: {\"action\": \"/login\", \"method\": \"POST\", \"username_field\": \"email\", \"password_field\": \"password\"}\n\n" +
		"If HTML has: <input name=\"user\"> and <input name=\"pass\" type=\"password\">\n" +
		"Return: {\"action\": \"/login\", \"method\": \"POST\", \"username_field\": \"user\", \"password_field\": \"pass\"}\n\n" +
		"OUTPUT FORMAT (JSON only, no markdown, no code blocks):\n" +
		"{\"action\": \"/login\", \"method\": \"POST\", \"username_field\": \"actual_name_from_html\", \"password_field\": \"actual_name_from_html\"}\n\n" +
		"CRITICAL: Output ONLY raw JSON. Do NOT wrap in ```json or ``` code blocks."
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
	return getFormattedPrompt("initial", map[string]interface{}{
		"target": target,
	})
}

// GetCommanderAnalyze returns the prompt for analyzing observations
func GetCommanderAnalyze(fromAgent, target, observation string) string {
	return getFormattedPrompt("analyze", map[string]interface{}{
		"from_agent":  fromAgent,
		"target":      target,
		"observation": observation,
	})
}

// GetReconDecision returns the prompt for Recon agent tool decision
func GetReconDecision(target, task string) string {
	return getFormattedPrompt("decision", map[string]interface{}{
		"target": target,
		"task":   task,
	})
}

// GetXSSAnalysis returns the prompt for XSS analysis
func GetXSSAnalysis(htmlSource string) string {
	return getFormattedPrompt("xss_analysis", map[string]interface{}{
		"html_source": htmlSource,
	})
}

// GetSQLiAnalysis returns the prompt for SQLi analysis
func GetSQLiAnalysis(htmlSource string) string {
	return getFormattedPrompt("sqli_analysis", map[string]interface{}{
		"html_source": htmlSource,
	})
}

// GetVerifyExtract returns the prompt for extracting vulnerability info
func GetVerifyExtract(report string) string {
	return getFormattedPrompt("extract", map[string]interface{}{
		"report": report,
	})
}

// GetPathTraversalAnalysis returns the prompt for Path Traversal analysis
func GetPathTraversalAnalysis(htmlSource string) string {
	return getFormattedPrompt("path_traversal", map[string]interface{}{
		"html_source": htmlSource,
	})
}

// GetWebAnalysis returns the prompt for Web vulnerability analysis (JSON output)
func GetWebAnalysis(httpResponse string) string {
	return getFormattedPrompt("web_analysis", map[string]interface{}{
		"http_response": httpResponse,
	})
}

// GetCommandInjectionAnalysis returns the prompt for Command Injection analysis
func GetCommandInjectionAnalysis(htmlSource string) string {
	return getFormattedPrompt("cmdi_analysis", map[string]interface{}{
		"html_source": htmlSource,
	})
}

// GetPlatformDetection returns the prompt for OS platform detection
func GetPlatformDetection(cmdOutput string) string {
	return getFormattedPrompt("platform_detect", map[string]interface{}{
		"cmd_output": cmdOutput,
	})
}

// GetFileUploadAnalysis returns the prompt for File Upload vulnerability analysis
func GetFileUploadAnalysis(htmlSource string) string {
	return getFormattedPrompt("file_upload", map[string]interface{}{
		"html_source": htmlSource,
	})
}

// GetCrawlAnalysis returns the prompt for web crawling and link extraction
func GetCrawlAnalysis(htmlContent string, baseURL string) string {
	return getFormattedPrompt("crawler", map[string]interface{}{
		"html_content": htmlContent,
		"base_url":     baseURL,
	})
}

// GetLoginFormAnalysis returns the prompt for login form detection and analysis
func GetLoginFormAnalysis(htmlContent string) string {
	return getFormattedPrompt("login_form", map[string]interface{}{
		"html_content": htmlContent,
	})
}
