package docker

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Executor runs commands in Docker containers
type Executor struct {
	client *client.Client
}

// NewExecutor creates a new Docker executor
func NewExecutor() (*Executor, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &Executor{client: cli}, nil
}

// RunTool executes a tool in a Docker container
// imageName: e.g., "cal/nmap:latest"
// cmd: e.g., ["nmap", "-p", "80", "example.com"]
func (e *Executor) RunTool(ctx context.Context, imageName string, cmd []string) (string, error) {
	log.Printf("[Docker] Using local image: %s\n", imageName)
	log.Printf("[Docker] Creating container with command: %v\n", cmd)

	// Create container
	resp, err := e.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: imageName,
			Cmd:   cmd,
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	containerID := resp.ID
	defer func() {
		// Cleanup: remove container after execution
		e.client.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{Force: true})
	}()

	log.Printf("[Docker] Starting container: %s\n", containerID[:12])

	// Start container
	_, err = e.client.ContainerStart(ctx, containerID, client.ContainerStartOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	// Wait for container to finish (polling approach)
	for {
		inspect, err := e.client.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to inspect container: %w", err)
		}

		// Check if container is still running
		if !inspect.Container.State.Running {
			if inspect.Container.State.ExitCode != 0 {
				log.Printf("[Docker] Container exited with code %d\n", inspect.Container.State.ExitCode)
			}
			break
		}

		time.Sleep(500 * time.Millisecond)
	}

	// Get logs
	out, err := e.client.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %w", err)
	}
	defer out.Close()

	// Read all output
	logs, err := io.ReadAll(out)
	if err != nil {
		return "", err
	}

	// Docker adds 8-byte headers to each log line: [type][padding][padding][padding][size*4]
	// Strip these headers to get clean output
	result := stripDockerHeaders(logs)

	log.Printf("[Docker] Container finished. Output length: %d bytes\n", len(result))
	return result, nil
}

// stripDockerHeaders removes Docker's 8-byte stream multiplexing headers
func stripDockerHeaders(data []byte) string {
	var cleanedData []byte
	i := 0

	for i < len(data) {
		if i+8 > len(data) {
			break
		}

		// Read the 4-byte size from header bytes 4-7 (big-endian)
		size := int(data[i+4])<<24 | int(data[i+5])<<16 | int(data[i+6])<<8 | int(data[i+7])

		// Skip the 8-byte header
		i += 8

		// Extract the actual data
		if i+size <= len(data) {
			cleanedData = append(cleanedData, data[i:i+size]...)
			i += size
		} else {
			// Incomplete data, just append what's left
			cleanedData = append(cleanedData, data[i:]...)
			break
		}
	}

	return string(cleanedData)
}

// Close cleans up the Docker client
func (e *Executor) Close() error {
	return e.client.Close()
}
