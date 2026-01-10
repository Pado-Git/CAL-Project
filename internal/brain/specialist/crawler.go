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
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
)

var crawlerMessageCounter atomic.Uint64

// CrawlerSpecialist is a specialist agent focused on web crawling and site mapping
type CrawlerSpecialist struct {
	id            string
	bus           bus.Bus
	brain         llm.LLM
	ctx           context.Context
	baseURL       string
	executor      tools.ToolExecutor
	sessionCookie string

	visitedURLs    map[string]bool
	discoveredURLs []string
	maxDepth       int
	maxPages       int
	mu             sync.RWMutex
}

// NewCrawlerSpecialist creates a new CrawlerSpecialist agent
func NewCrawlerSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, baseURL string, executor tools.ToolExecutor, sessionCookie string) *CrawlerSpecialist {
	return &CrawlerSpecialist{
		id:             id,
		bus:            eventBus,
		brain:          llmClient,
		ctx:            ctx,
		baseURL:        baseURL,
		executor:       executor,
		sessionCookie:  sessionCookie,
		visitedURLs:    make(map[string]bool),
		discoveredURLs: make([]string, 0),
		maxDepth:       5,
		maxPages:       100,
	}
}

func (c *CrawlerSpecialist) ID() string {
	return c.id
}

func (c *CrawlerSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (c *CrawlerSpecialist) Run() error {
	log.Printf("[%s] Online. Crawling website from: %s\n", c.id, c.baseURL)
	return nil
}

func (c *CrawlerSpecialist) OnEvent(event bus.Event) {
	// Only process commands directed to this agent
	if event.Type == bus.Command && event.ToAgent == c.id {
		log.Printf("[%s] Received command: %v\n", c.id, event.Payload)
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[%s] PANIC in executeTask: %v\n%s\n", c.id, rec, debug.Stack())
					c.reportError(event.FromAgent, fmt.Errorf("task panicked: %v", rec))
				}
			}()
			c.executeTask(event)
		}()
	}
}

// executeTask performs web crawling
func (c *CrawlerSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", c.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", c.id, taskDesc)

	if c.executor == nil {
		c.reportObservation(cmdEvent.FromAgent, "Crawling skipped (Docker executor unavailable)")
		return
	}

	// Start BFS crawling from base URL
	log.Printf("[%s] Starting BFS crawl from: %s\n", c.id, c.baseURL)
	c.crawlURL(c.baseURL, 0)

	// Force-crawl common upload endpoints that might not be linked
	c.forceCrawlCommonEndpoints()

	// Report discovered URLs
	c.reportDiscoveredURLs(cmdEvent.FromAgent)
}

// crawlURL performs recursive BFS crawling
func (c *CrawlerSpecialist) crawlURL(currentURL string, depth int) {
	// Check depth limit
	if depth > c.maxDepth {
		log.Printf("[%s] Max depth (%d) reached, stopping\n", c.id, c.maxDepth)
		return
	}

	// Check page limit
	c.mu.RLock()
	pageCount := len(c.visitedURLs)
	c.mu.RUnlock()

	if pageCount >= c.maxPages {
		log.Printf("[%s] Max pages (%d) reached, stopping\n", c.id, c.maxPages)
		return
	}

	// Check if already visited
	c.mu.Lock()
	if c.visitedURLs[currentURL] {
		c.mu.Unlock()
		return
	}
	c.visitedURLs[currentURL] = true
	c.mu.Unlock()

	// Filter static resources
	if c.isStaticResource(currentURL) {
		log.Printf("[%s] Skipping static resource: %s\n", c.id, currentURL)
		return
	}

	// Check if same domain
	if !c.isSameDomain(currentURL) {
		log.Printf("[%s] Skipping different domain: %s\n", c.id, currentURL)
		return
	}

	log.Printf("[%s] Crawling [depth=%d]: %s\n", c.id, depth, currentURL)

	// Fetch HTTP response
	httpOutput, err := tools.HTTPGetWithCookie(c.ctx, c.executor, currentURL, c.sessionCookie)
	if err != nil {
		log.Printf("[%s] HTTP request failed for %s: %v\n", c.id, currentURL, err)
		return
	}

	// Check for login form
	if c.hasLoginForm(httpOutput) {
		log.Printf("[%s] 🔐 Login form detected at: %s\n", c.id, currentURL)
		c.reportObservation("Commander-01", fmt.Sprintf("LOGIN_FORM_FOUND: %s", currentURL))
	}

	// Extract links using LLM
	links := c.extractLinks(httpOutput, currentURL)

	// Add discovered links
	c.mu.Lock()
	for _, link := range links {
		if !c.visitedURLs[link] {
			c.discoveredURLs = append(c.discoveredURLs, link)
		}
	}
	c.mu.Unlock()

	// Recursively crawl discovered links
	for _, link := range links {
		c.crawlURL(link, depth+1)
	}
}

// extractLinks uses LLM to extract all links from HTML
func (c *CrawlerSpecialist) extractLinks(httpResponse string, baseURL string) []string {
	// Limit response size for LLM
	responseToAnalyze := httpResponse
	if len(httpResponse) > 8000 {
		responseToAnalyze = httpResponse[:8000]
	}

	prompt := prompts.GetCrawlAnalysis(responseToAnalyze, baseURL)

	analysis, err := c.brain.Generate(c.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM link extraction failed: %v\n", c.id, err)
		return []string{}
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
		Links []string `json:"links"`
	}

	if err := json.Unmarshal([]byte(analysis), &result); err != nil {
		log.Printf("[%s] Failed to parse LLM JSON: %v\n", c.id, err)
		log.Printf("[%s] Raw LLM response: %s\n", c.id, analysis)
		return []string{}
	}

	// Resolve relative URLs to absolute
	absoluteLinks := make([]string, 0)
	for _, link := range result.Links {
		absoluteURL := c.resolveURL(baseURL, link)
		if absoluteURL != "" {
			absoluteLinks = append(absoluteLinks, absoluteURL)
		}
	}

	log.Printf("[%s] Extracted %d links from %s\n", c.id, len(absoluteLinks), baseURL)
	return absoluteLinks
}

// hasLoginForm detects if HTML contains a login form
func (c *CrawlerSpecialist) hasLoginForm(htmlContent string) bool {
	lowerHTML := strings.ToLower(htmlContent)

	// Exclude register/signup forms
	if strings.Contains(lowerHTML, "register") ||
		strings.Contains(lowerHTML, "sign up") ||
		strings.Contains(lowerHTML, "signup") ||
		strings.Contains(lowerHTML, "create account") {
		return false
	}

	// Check for password input
	hasPasswordInput := strings.Contains(lowerHTML, `type="password"`) ||
		strings.Contains(lowerHTML, `type='password'`)

	if !hasPasswordInput {
		return false
	}

	// Require login-related keywords for confirmation
	hasLoginKeyword := strings.Contains(lowerHTML, "login") ||
		strings.Contains(lowerHTML, "log in") ||
		strings.Contains(lowerHTML, "sign in") ||
		strings.Contains(lowerHTML, "signin")

	return hasLoginKeyword
}

// isStaticResource checks if URL points to static file
func (c *CrawlerSpecialist) isStaticResource(urlStr string) bool {
	staticExtensions := []string{".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf"}
	lowerURL := strings.ToLower(urlStr)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerURL, ext) {
			return true
		}
	}
	return false
}

// isSameDomain checks if URL belongs to the same domain as base URL
func (c *CrawlerSpecialist) isSameDomain(targetURL string) bool {
	baseURLParsed, err := url.Parse(c.baseURL)
	if err != nil {
		return false
	}

	targetURLParsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	return baseURLParsed.Host == targetURLParsed.Host
}

// resolveURL converts relative URLs to absolute URLs
func (c *CrawlerSpecialist) resolveURL(base string, href string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}

	hrefURL, err := url.Parse(href)
	if err != nil {
		return ""
	}

	// Resolve relative to base
	absoluteURL := baseURL.ResolveReference(hrefURL)
	return absoluteURL.String()
}

// forceCrawlCommonEndpoints attempts to discover common upload/admin endpoints
// that might not be linked in the HTML but are commonly used
func (c *CrawlerSpecialist) forceCrawlCommonEndpoints() {
	// Common upload endpoint patterns
	commonPaths := []string{
		"/act/write.php",
		"/act/upload.php",
		"/upload.php",
		"/upload",
		"?p=write.php",
		"?p=upload.php",
		"/admin/upload.php",
		"/admin/write.php",
	}

	baseURLParsed, err := url.Parse(c.baseURL)
	if err != nil {
		log.Printf("[%s] Failed to parse base URL for force-crawling: %v\n", c.id, err)
		return
	}

	log.Printf("[%s] 🔍 Force-crawling common upload endpoints...\n", c.id)

	for _, path := range commonPaths {
		var testURL string

		if strings.HasPrefix(path, "?") {
			// Query parameter: append to base URL
			testURL = c.baseURL + path
		} else {
			// Path: construct absolute URL
			testURL = fmt.Sprintf("%s://%s%s", baseURLParsed.Scheme, baseURLParsed.Host, path)
		}

		// Check if already visited
		c.mu.RLock()
		alreadyVisited := c.visitedURLs[testURL]
		c.mu.RUnlock()

		if !alreadyVisited {
			log.Printf("[%s] 🔍 Force-crawling: %s\n", c.id, testURL)
			// Crawl at depth 1 (not deep recursion)
			c.crawlURL(testURL, 1)
		}
	}
}

// reportDiscoveredURLs sends JSON report of all discovered URLs
func (c *CrawlerSpecialist) reportDiscoveredURLs(toAgent string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	report := struct {
		BaseURL         string   `json:"base_url"`
		DiscoveredURLs  []string `json:"discovered_urls"`
		TotalCount      int      `json:"total_count"`
	}{
		BaseURL:        c.baseURL,
		DiscoveredURLs: c.discoveredURLs,
		TotalCount:     len(c.discoveredURLs),
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		log.Printf("[%s] Failed to marshal JSON report: %v\n", c.id, err)
		return
	}

	observation := fmt.Sprintf("CRAWLER_JSON_START\n%s\nCRAWLER_JSON_END", string(jsonData))
	log.Printf("[%s] 🕷️ Discovered %d URLs total\n", c.id, report.TotalCount)

	c.reportObservation(toAgent, observation)
}

func (c *CrawlerSpecialist) reportObservation(toAgent string, observation string) {
	msgID := crawlerMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", c.id, msgID),
		FromAgent: c.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	c.bus.Publish(toAgent, event)
}

func (c *CrawlerSpecialist) reportError(toAgent string, err error) {
	msgID := crawlerMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", c.id, msgID),
		FromAgent: c.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	c.bus.Publish(toAgent, event)
}
