package trt

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// RemoteExecutor implements an interface compatible with Cai's requirements
// by delegating execution to a remote TRT Agent.
type RemoteExecutor struct {
	client        *Client
	paw           string
	agentPlatform string // "windows" or "linux"
}

// NewRemoteExecutor creates a new executor for a specific agent
func NewRemoteExecutor(client *Client, paw string, platform string) *RemoteExecutor {
	return &RemoteExecutor{
		client:        client,
		paw:           paw,
		agentPlatform: platform,
	}
}

// RunTool executes a command on the remote agent.
// Note: 'imageName' is ignored or treated as 'tool type' context in this remote scenario.
// 'cmd' args are joined to form the command string.
func (e *RemoteExecutor) RunTool(ctx context.Context, imageName string, cmd []string) (string, error) {
	// Construct command string with proper escaping
	// Arguments containing special characters (&, |, <, >, etc.) need to be quoted
	var escapedArgs []string
	for _, arg := range cmd {
		if needsQuoting(arg) {
			escapedArgs = append(escapedArgs, fmt.Sprintf("\"%s\"", arg))
		} else {
			escapedArgs = append(escapedArgs, arg)
		}
	}
	fullCommand := strings.Join(escapedArgs, " ")

	// Determine executor based on platform
	executorName := "command_prompt"
	if strings.ToLower(e.agentPlatform) == "linux" || strings.ToLower(e.agentPlatform) == "darwin" {
		executorName = "bash"
	} else {
		// Windows
		executorName = "command_prompt"
		// Check if we want powershell
		if strings.Contains(strings.ToLower(imageName), "powershell") {
			executorName = "powershell"
		}
	}

	log.Printf("[TRT] Executing on %s: %s (Executor: %s)", e.paw, fullCommand, executorName)

	// Send command
	linkID, err := e.client.RunCommand("0", e.paw, e.agentPlatform, executorName, fullCommand)
	if err != nil {
		return "", fmt.Errorf("failed to send command to agent: %w", err)
	}

	// Poll for result
	// We poll for up to 'timeout' seconds.
	timeout := 120 * time.Second
	interval := 2 * time.Second
	startTime := time.Now()

	for time.Since(startTime) < timeout {
		// check context
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		result, err := e.client.GetCommandResult(linkID)
		if err != nil {
			log.Printf("[TRT] Polling error: %v", err)
			// Don't fail immediately on polling error, might be temporary
		} else if result != nil && result.ID != "" {
			// Check status? result object has Success bool and Results string.
			// Toncal spec says: status -1 (pending), -3 (delivered?), 0 (done).
			// But GetCommandResult returns the *result object*, which likely implies it's done if it exists.
			// If API returns 404 or empty list, it means no result yet.
			// Our client implementation checks for list.

			// If result.Results is present, return it.
			return result.Results, nil
		}

		time.Sleep(interval)
	}

	return "", fmt.Errorf("command execution timed out after %v", timeout)
}

func (e *RemoteExecutor) Close() error {
	return nil
}

// needsQuoting checks if an argument contains special shell characters
// that require quoting to prevent shell interpretation
func needsQuoting(arg string) bool {
	// Core special characters that MUST be quoted for shell safety
	// Note: ?, =, () are excluded as they're safe in most contexts (URLs, etc)
	// &, |, ;, space are critical for preventing command injection
	specialChars := "&|<>; $`\\\""
	for _, char := range specialChars {
		if strings.ContainsRune(arg, char) {
			return true
		}
	}
	return false
}
