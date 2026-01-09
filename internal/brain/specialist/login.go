package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/tools"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
)

var loginMessageCounter atomic.Uint64

// LoginSpecialist is a specialist agent focused on automatic login
type LoginSpecialist struct {
	id          string
	bus         bus.Bus
	brain       llm.LLM
	ctx         context.Context
	loginURL    string
	executor    tools.ToolExecutor
	credentials map[string]string
}

// NewLoginSpecialist creates a new LoginSpecialist agent
func NewLoginSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, loginURL string, executor tools.ToolExecutor, credentials map[string]string) *LoginSpecialist {
	return &LoginSpecialist{
		id:          id,
		bus:         eventBus,
		brain:       llmClient,
		ctx:         ctx,
		loginURL:    loginURL,
		executor:    executor,
		credentials: credentials,
	}
}

func (l *LoginSpecialist) ID() string {
	return l.id
}

func (l *LoginSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (l *LoginSpecialist) Run() error {
	log.Printf("[%s] Online. Attempting login on: %s\n", l.id, l.loginURL)
	return nil
}

func (l *LoginSpecialist) OnEvent(event bus.Event) {
	// Only process commands directed to this agent
	if event.Type == bus.Command && event.ToAgent == l.id {
		log.Printf("[%s] Received command: %v\n", l.id, event.Payload)
		go l.executeTask(event)
	}
}

// executeTask performs automatic login
func (l *LoginSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", l.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", l.id, taskDesc)

	if l.executor == nil {
		l.reportObservation(cmdEvent.FromAgent, "Login attempt skipped (Docker executor unavailable)")
		return
	}

	// Step 1: Fetch login page
	log.Printf("[%s] Fetching login form from: %s\n", l.id, l.loginURL)
	loginPageHTML, err := tools.SimpleHTTPGet(l.ctx, l.executor, l.loginURL)
	if err != nil {
		log.Printf("[%s] Failed to fetch login page: %v\n", l.id, err)
		l.reportError(cmdEvent.FromAgent, err)
		return
	}

	// Step 2: Extract login form details using LLM
	log.Printf("[%s] Analyzing login form...\n", l.id)
	formData := l.extractLoginForm(loginPageHTML)
	if formData == nil {
		log.Printf("[%s] No login form detected\n", l.id)
		l.reportObservation(cmdEvent.FromAgent, "No login form found")
		return
	}

	// Step 3: Attempt login
	log.Printf("[%s] Attempting login with credentials...\n", l.id)
	loginResponse, err := l.attemptLogin(formData)
	if err != nil {
		log.Printf("[%s] Login attempt failed: %v\n", l.id, err)
		l.reportError(cmdEvent.FromAgent, err)
		return
	}

	// Step 4: Extract session cookie
	sessionCookie := l.extractCookie(loginResponse)
	if sessionCookie == "" {
		log.Printf("[%s] No session cookie found in response\n", l.id)
		l.reportObservation(cmdEvent.FromAgent, "Login failed: No session cookie")
		return
	}

	// Step 5: Verify login success
	if !l.isLoginSuccessful(loginResponse) {
		log.Printf("[%s] Login verification failed\n", l.id)
		l.reportObservation(cmdEvent.FromAgent, "Login failed: Invalid credentials or blocked")
		return
	}

	// Step 6: Report session cookie
	log.Printf("[%s] ✅ Login successful! Session cookie: %s\n", l.id, l.maskCookie(sessionCookie))
	l.reportSessionCookie(cmdEvent.FromAgent, sessionCookie)
}

// extractLoginForm uses LLM to parse login form structure
func (l *LoginSpecialist) extractLoginForm(htmlContent string) map[string]string {
	// Limit response size for LLM
	responseToAnalyze := htmlContent
	if len(htmlContent) > 8000 {
		responseToAnalyze = htmlContent[:8000]
	}

	prompt := prompts.GetLoginFormAnalysis(responseToAnalyze)

	analysis, err := l.brain.Generate(l.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM form analysis failed: %v\n", l.id, err)
		return nil
	}

	// Remove markdown code blocks if present
	analysis = strings.TrimSpace(analysis)
	if strings.HasPrefix(analysis, "```json") {
		analysis = strings.TrimPrefix(analysis, "```json")
		analysis = strings.TrimSuffix(analysis, "```")
		analysis = strings.TrimSpace(analysis)
	} else if strings.HasPrefix(analysis, "```") {
		analysis = strings.TrimPrefix(analysis, "```")
		analysis = strings.TrimSuffix(analysis, "```")
		analysis = strings.TrimSpace(analysis)
	}

	// Parse JSON response
	var result struct {
		Action        string `json:"action"`
		Method        string `json:"method"`
		UsernameField string `json:"username_field"`
		PasswordField string `json:"password_field"`
	}

	if err := json.Unmarshal([]byte(analysis), &result); err != nil {
		log.Printf("[%s] Failed to parse LLM JSON: %v\n", l.id, err)
		log.Printf("[%s] Raw LLM response: %s\n", l.id, analysis)
		return nil
	}

	log.Printf("[%s] Form detected: action=%s, method=%s, username_field=%s, password_field=%s\n",
		l.id, result.Action, result.Method, result.UsernameField, result.PasswordField)

	formData := make(map[string]string)
	formData["action"] = result.Action
	formData["method"] = strings.ToUpper(result.Method)

	// Map credentials to actual HTML field names
	if result.UsernameField != "" {
		if email, exists := l.credentials["email"]; exists {
			formData[result.UsernameField] = email
		}
	}
	if result.PasswordField != "" {
		if password, exists := l.credentials["password"]; exists {
			formData[result.PasswordField] = password
		}
	}

	return formData
}

// attemptLogin performs POST request with credentials
func (l *LoginSpecialist) attemptLogin(formData map[string]string) (string, error) {
	action := formData["action"]
	method := formData["method"]

	// Build login URL
	loginURL := l.loginURL
	if !strings.HasPrefix(action, "http") {
		// Relative path
		if strings.HasPrefix(action, "/") {
			// Absolute path from root
			loginURL = l.getBaseURL() + action
		} else {
			// Relative to current directory
			// Remove trailing slash from loginURL if present
			baseDir := strings.TrimSuffix(l.loginURL, "/")

			// If action starts with ./, remove it
			cleanAction := strings.TrimPrefix(action, "./")

			// If baseDir ends with a file (no trailing /), remove the file part
			if !strings.HasSuffix(l.loginURL, "/") {
				// loginURL is like http://example.com/page.php
				// Get the directory part
				if lastSlash := strings.LastIndex(baseDir, "/"); lastSlash != -1 {
					baseDir = baseDir[:lastSlash]
				}
			}

			loginURL = baseDir + "/" + cleanAction
		}
	} else {
		loginURL = action
	}

	// Build POST data
	postData := make(map[string]string)
	for key, value := range formData {
		if key != "action" && key != "method" {
			postData[key] = value
		}
	}

	log.Printf("[%s] POST %s with data: %v\n", l.id, loginURL, l.maskPostData(postData))

	if method == "POST" {
		return tools.HTTPPost(l.ctx, l.executor, loginURL, postData, "")
	}

	// Fallback to GET (rare)
	return tools.SimpleHTTPGet(l.ctx, l.executor, loginURL)
}

// extractCookie extracts session cookie from Set-Cookie header
func (l *LoginSpecialist) extractCookie(httpResponse string) string {
	lines := strings.Split(httpResponse, "\n")
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "set-cookie:") {
			// Extract cookie value - handle both cases
			// Format: Set-Cookie: session=abc123; Path=/; HttpOnly
			cookieValue := line

			// Remove "Set-Cookie: " prefix (case insensitive)
			if idx := strings.Index(lowerLine, "set-cookie:"); idx != -1 {
				cookieValue = line[idx+len("set-cookie:"):]
			}

			cookieValue = strings.TrimSpace(cookieValue)

			// Extract only the key=value part (before first semicolon)
			if idx := strings.Index(cookieValue, ";"); idx != -1 {
				cookieValue = cookieValue[:idx]
			}

			cookieValue = strings.TrimSpace(cookieValue)
			return cookieValue
		}
	}
	return ""
}

// isLoginSuccessful uses heuristics to verify login success
func (l *LoginSpecialist) isLoginSuccessful(httpResponse string) bool {
	lowerResponse := strings.ToLower(httpResponse)

	// 1. Check for failure indicators FIRST (priority)
	failureIndicators := []string{
		"login failed",
		"invalid password",
		"invalid credentials",
		"incorrect username",
		"authentication failed",
		"alert('login failed')", // JavaScript alert
		"alert(\"login failed\")",
		"wrong password",
		"wrong username",
		"access denied",
	}

	for _, indicator := range failureIndicators {
		if strings.Contains(lowerResponse, indicator) {
			return false
		}
	}

	// 2. Check for success indicators
	successIndicators := []string{
		"window.location.href", // JavaScript redirect (strong indicator)
		"window.location=",
		"welcome",
		"dashboard",
		"logout",
		"account",
		"profile",
		"success",
	}

	for _, indicator := range successIndicators {
		if strings.Contains(lowerResponse, indicator) {
			return true
		}
	}

	// 3. If Set-Cookie exists and no failure indicators, assume success
	hasCookie := strings.Contains(lowerResponse, "set-cookie:")
	return hasCookie
}

// getBaseURL extracts base URL from login URL
func (l *LoginSpecialist) getBaseURL() string {
	// Extract http://host:port from URL
	if idx := strings.Index(l.loginURL, "://"); idx != -1 {
		afterScheme := l.loginURL[idx+3:]
		if slashIdx := strings.Index(afterScheme, "/"); slashIdx != -1 {
			return l.loginURL[:idx+3+slashIdx]
		}
		return l.loginURL
	}
	return l.loginURL
}

// maskCookie masks cookie value for logging
func (l *LoginSpecialist) maskCookie(cookie string) string {
	if len(cookie) > 20 {
		return cookie[:10] + "***" + cookie[len(cookie)-5:]
	}
	return cookie[:5] + "***"
}

// maskPostData masks sensitive data for logging
func (l *LoginSpecialist) maskPostData(data map[string]string) map[string]string {
	masked := make(map[string]string)
	for key, value := range data {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "pass") {
			masked[key] = "***"
		} else {
			masked[key] = value
		}
	}
	return masked
}

// reportSessionCookie sends session cookie and base URL to Commander
func (l *LoginSpecialist) reportSessionCookie(toAgent string, cookie string) {
	observation := fmt.Sprintf("SESSION_COOKIE_START\nurl: %s\ncookie: %s\nSESSION_COOKIE_END", l.loginURL, cookie)
	l.reportObservation(toAgent, observation)
}

func (l *LoginSpecialist) reportObservation(toAgent string, observation string) {
	msgID := loginMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", l.id, msgID),
		FromAgent: l.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	l.bus.Publish(toAgent, event)
}

func (l *LoginSpecialist) reportError(toAgent string, err error) {
	msgID := loginMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", l.id, msgID),
		FromAgent: l.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	l.bus.Publish(toAgent, event)
}
