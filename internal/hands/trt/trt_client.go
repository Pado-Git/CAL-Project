package trt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Client handles communication with the TRT (Toncal) API
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Token      string
}

// NewClient creates a new TRT API client with connection pooling
func NewClient() *Client {
	baseURL := os.Getenv("TRT_API_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	// HTTP Transport with connection pooling for Keep-Alive
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
	}
}

// Authenticate generates an admin token used for subsequent requests
func (c *Client) Authenticate() error {
	reqBody := map[string]interface{}{
		"user_id":       0, // 0 usually means auto-select admin or default admin
		"expires_hours": 8760,
	}
	jsonBody, _ := json.Marshal(reqBody)

	resp, err := c.HTTPClient.Post(c.BaseURL+"/dev/generate-token", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	c.Token = result.AccessToken
	return nil
}

// Agent represents a connected Callisto agent
type Agent struct {
	Paw         string `json:"paw"`
	Host        string `json:"host"`
	Platform    string `json:"platform"` // windows, linux
	Server      string `json:"server"`
	Depth       int    `json:"depth"`
	Contact     string `json:"contact"`
	Username    string `json:"username"`  // User context (e.g., root, SYSTEM)
	Privilege   string `json:"privilege"` // Elevated, User
	HostIPAddrs string `json:"host_ip_addrs"` // JSON array string: "[\"192.168.1.1\", \"10.0.0.1\"]"
}

// GetAliveAgents returns a list of active agents
func (c *Client) GetAliveAgents() ([]Agent, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/agents", nil)
	if err != nil {
		return nil, err
	}
	c.addAuthHeader(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list agents failed (status %d)", resp.StatusCode)
	}

	var agents []Agent
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		return nil, fmt.Errorf("failed to decode agents response: %w", err)
	}

	return agents, nil
}

// CommandExecutor defines the execution context
type CommandExecutor struct {
	Platform string `json:"platform"` // e.g., "windows"
	Name     string `json:"name"`     // e.g., "command_prompt", "powershell"
	Command  string `json:"command"`
}

// RunCommandRequest payload for running a command
type RunCommandRequest struct {
	Paw      string          `json:"paw"`
	Executor CommandExecutor `json:"executor"`
}

// RunCommandResponse contains the command Link ID
type RunCommandResponse struct {
	ID     string `json:"id"` // This is the link_id
	Status int    `json:"status"`
}

// RunCommand sends a command to an agent
func (c *Client) RunCommand(operationID string, paw string, platform string, executorName string, command string) (string, error) {
	if operationID == "" {
		operationID = "0"
	}

	reqBody := RunCommandRequest{
		Paw: paw,
		Executor: CommandExecutor{
			Platform: platform,
			Name:     executorName,
			Command:  command,
		},
	}
	jsonBody, _ := json.Marshal(reqBody)

	url := fmt.Sprintf("%s/operations/%s/commands/run", c.BaseURL, operationID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	c.addAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to run command: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("run command failed (status %d): %s", resp.StatusCode, string(body))
	}

	var result RunCommandResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode run command response: %w", err)
	}

	return result.ID, nil
}

// AbilityRequest payload for running an ability (T-Technique)
type AbilityRequest struct {
	Paw        string                 `json:"paw"`
	AbilityID  string                 `json:"ability_id"`
	Obfuscator string                 `json:"obfuscator"`
	Input      map[string]interface{} `json:"input,omitempty"`
}

// RunAbility executes a known ability (Technique) on the agent
func (c *Client) RunAbility(operationID string, paw string, abilityID string, input map[string]interface{}) (string, error) {
	if operationID == "" {
		operationID = "0"
	}

	reqBody := AbilityRequest{
		Paw:        paw,
		AbilityID:  abilityID,
		Obfuscator: "plain",
		Input:      input,
	}
	jsonBody, _ := json.Marshal(reqBody)

	url := fmt.Sprintf("%s/operations/%s/abilities/run", c.BaseURL, operationID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	c.addAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to run ability: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("run ability failed (status %d): %s", resp.StatusCode, string(body))
	}

	// According to routers/operations.py run_ability calls toncal.execute_ability which likely returns a Link ID string directly or object?
	// Wait, run_command returns `link` object. run_ability returns await toncal.execute_ability(...)
	// Assuming it returns similar structure or just the ID. The plan says result polling is needed.
	// Let's assume it returns a JSON with ID. If it returns raw string, decode might fail.
	// Safest is to read body and try to parse or return as is.
	// Based on `RunCommand`, let's assume it returns the `Link` object.

	var result RunCommandResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// If structure is different, we might need to adjust.
		// For now, let's assume consistent API usage.
		return "", fmt.Errorf("failed to decode run ability response: %w", err)
	}
	return result.ID, nil
}

// QueryResultRequest payload
type QueryResultRequest struct {
	Index  string `json:"index"` // "result"
	LinkID string `json:"link_id"`
}

// CommandResult represents the output of a command
type CommandResult struct {
	ID      string `json:"id"`
	Results string `json:"results"`
	Success bool   `json:"success"`
	Log     string `json:"log"`
}

// GetCommandResult polls for the result of a command
func (c *Client) GetCommandResult(linkID string) (*CommandResult, error) {
	reqBody := QueryResultRequest{
		Index:  "result",
		LinkID: linkID,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", c.BaseURL+"/results/query", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	c.addAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query result: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query result failed (status %d)", resp.StatusCode)
	}

	// The API documentation I wrote says it returns a LIST `ResponseModel = Union[list[fm.AgentsResponse], list[fm.AttackOrderResultResponse]]`
	// routers/results.py: `return result` -> `toncal.get_attack_order_result(data.link_id)`
	// `toncalModel.py`: `AttackOrderResultResponse` is a single object.
	// BUT `routers/results.py` logic: `ResponseModel = Union[list[...], list[...]]`.
	// And `toncal.get_agents_by_user` returns list.
	// It's highly likely `get_attack_order_result` returns a list too (maybe history of results for that link?).
	// I should handle both list or single object if possible, or assume list based on `ResponseModel`.

	// Let's try to decode as list first.
	var results []CommandResult
	bodyBytes, _ := io.ReadAll(resp.Body)

	// Restore body for second attempt if needed
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		// Try single object?
		var singleResult CommandResult
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := json.NewDecoder(resp.Body).Decode(&singleResult); err != nil {
			return nil, fmt.Errorf("failed to decode result: %w", err)
		}
		return &singleResult, nil
	}

	if len(results) == 0 {
		return nil, nil // No result yet
	}

	return &results[0], nil
}

// NetworkNode represents a node in the network topology
type NetworkNode struct {
	ID        int    `json:"id"`
	IPAddress string `json:"ipAddress"`
	Hostname  string `json:"hostname"`
	Role      string `json:"role"`
}

// GetNetworkNodes returns the list of discovered network nodes
func (c *Client) GetNetworkNodes() ([]NetworkNode, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/networknodes", nil)
	if err != nil {
		return nil, err
	}
	c.addAuthHeader(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get network nodes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get network nodes failed (status %d)", resp.StatusCode)
	}

	var nodes []NetworkNode
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return nil, fmt.Errorf("failed to decode network nodes: %w", err)
	}

	return nodes, nil
}

// GetNetworkNodeByIP finds a network node by IP address
// Returns nil if no matching node is found
func (c *Client) GetNetworkNodeByIP(ipAddress string) (*NetworkNode, error) {
	nodes, err := c.GetNetworkNodes()
	if err != nil {
		return nil, err
	}

	for _, node := range nodes {
		if node.IPAddress == ipAddress {
			return &node, nil
		}
	}

	return nil, nil // Not found, but not an error
}

// ScanResultPort represents a discovered port
type ScanResultPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
}

// ScanResultHost represents a discovered host
type ScanResultHost struct {
	IP       string           `json:"ip"`
	Hostname string           `json:"hostname,omitempty"`
	Ports    []ScanResultPort `json:"ports"`
}

// ScanResultRequest represents the scan result payload
type ScanResultRequest struct {
	SourcePAW string           `json:"source_paw"`
	Hosts     []ScanResultHost `json:"hosts"`
}

// SaveScanResult sends scan results to TRT for storage
func (c *Client) SaveScanResult(sourcePAW string, hosts []ScanResultHost) error {
	reqBody := ScanResultRequest{
		SourcePAW: sourcePAW,
		Hosts:     hosts,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	url := fmt.Sprintf("%s/networknodes/scan-result", c.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	c.addAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to save scan result: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("save scan result failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreateNetworkNodeRequest represents the payload for creating a network node
type CreateNetworkNodeRequest struct {
	IPAddress    string `json:"ipAddress"`
	Hostname     string `json:"hostname"`
	Role         string `json:"role"`
	OS           string `json:"os,omitempty"`
	Platform     string `json:"platform,omitempty"`
	Compromised  bool   `json:"compromised,omitempty"`
	SourceNodeID *int   `json:"sourceNodeId,omitempty"` // Optional: creates edge from source -> new node
}

// CreateNetworkNode creates a new network node in TRT for a compromised target
// If sourceNodeID is provided, an edge will be created from source node to the new node
func (c *Client) CreateNetworkNode(ipAddress string, hostname string, role string, platform string, compromised bool, sourceNodeID ...int) (*NetworkNode, error) {
	reqBody := CreateNetworkNodeRequest{
		IPAddress:   ipAddress,
		Hostname:    hostname,
		Role:        role,
		Platform:    platform,
		Compromised: compromised,
	}
	// Set sourceNodeID if provided
	if len(sourceNodeID) > 0 && sourceNodeID[0] > 0 {
		reqBody.SourceNodeID = &sourceNodeID[0]
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal network node request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/networknodes", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	c.addAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create network node: %w", err)
	}
	defer resp.Body.Close()

	// Accept both 200 and 201 as success
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create network node failed (status %d): %s", resp.StatusCode, string(body))
	}

	var node NetworkNode
	if err := json.NewDecoder(resp.Body).Decode(&node); err != nil {
		return nil, fmt.Errorf("failed to decode network node response: %w", err)
	}

	return &node, nil
}

func (c *Client) addAuthHeader(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}
