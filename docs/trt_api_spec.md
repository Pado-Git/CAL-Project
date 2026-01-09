# TRT (Toncal) API Specification for Cai Integration

This document outlines the TRT API endpoints used by Cai to control the Attacker Agent.

## Base URL
`http://localhost:8080` (Default)

## Authentication
Cai uses a JWT Token to authenticate with TRT.

### Generate Admin Token (Dev/Test)
*   **Endpoint**: `POST /dev/generate-token`
*   **Description**: Generates a long-lived JWT token for the Admin user.
*   **Request Body**:
    ```json
    {
      "user_id": 0,
      "expires_hours": 8760
    }
    ```
*   **Response**:
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIs...",
      "token_type": "bearer",
      "user": { ... },
      "expires_in": "8760 hours"
    }
    ```

## Agents

### List Alive Agents
*   **Endpoint**: `GET /agents`
*   **Headers**: `Authorization: Bearer <token>`
*   **Description**: Returns a list of currently active agents.
*   **Response**:
    ```json
    [
      {
        "paw": "agent_unique_id",
        "host": "hostname",
        "platform": "windows",
        "server": "http://172.16.x.x",
        "contact": "HTTP",
        ...
      }
    ]
    ```

## Operations & Commands

### Execute Command
*   **Endpoint**: `POST /operations/{operation_id}/commands/run`
*   **Headers**: `Authorization: Bearer <token>`
*   **Description**: Sends a command to a specific agent. Use `operation_id="0"` for ad-hoc commands.
*   **Request Body**:
    ```json
    {
      "paw": "agent_unique_id",
      "executor": {
        "platform": "windows",  // or "linux"
        "name": "command_prompt", // or "powershell", "bash", "python"
        "command": "whoami"
      }
    }
    ```
    *Note: `command` should be the raw command string. TRT handles base64 encoding if needed by the agent protocol, but check `executor.go` in agent if double encoding is needed.*

*   **Response**:
    ```json
    {
      "id": "command_link_id", // Use this ID to query results
      "status": -1,
      ...
    }
    ```

### Execute Ability (T-Technique)
*   **Endpoint**: `POST /operations/{operation_id}/abilities/run`
*   **Headers**: `Authorization: Bearer <token>`
*   **Description**: Executes a pre-defined ability (e.g., T1595.001).
*   **Request Body**:
    ```json
    {
      "paw": "agent_unique_id",
      "ability_id": "T1595.001",
      "obfuscator": "plain",
      "input": {
        "targetIp": "192.168.1.0/24"
      }
    }
    ```

## Results

### Query Command Result
*   **Endpoint**: `POST /results/query`
*   **Headers**: `Authorization: Bearer <token>`
*   **Description**: Retrieves the output of an executed command.
*   **Request Body**:
    ```json
    {
      "index": "result",
      "link_id": "command_link_id"
    }
    ```
*   **Response**:
    ```json
    [
       {
          "id": "command_link_id",
          "results": "nt authority\\system\n",
          "success": true,
          "log": "..."
       }
    ]
    ```
    *(Note: Returns a list, usually with one item)*

## Network Topology

### List Network Nodes
*   **Endpoint**: `GET /networknodes`
*   **Headers**: `Authorization: Bearer <token>`
*   **Description**: Returns known network nodes, including those discovered by scans.
*   **Response**:
    ```json
    [
      {
        "id": 1,
        "ipAddress": "192.168.1.10",
        "hostname": "kali",
        "role": "attacker",
        "ports": [
           {
             "port_number": 80,
             "service_name": "http",
             "state": "open"
           }
        ]
      }
    ]
    ```
