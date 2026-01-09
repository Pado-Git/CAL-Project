#!/bin/bash
# CallistoAgent Linux Deployment Script
# Variables: {{AGENT_URL}}, {{AGENT_PATH}}

AGENT_URL="{{AGENT_URL}}"
AGENT_PATH="{{AGENT_PATH}}"

# Download agent (try curl first, then wget)
curl -s -o "$AGENT_PATH" "$AGENT_URL" || wget -q -O "$AGENT_PATH" "$AGENT_URL"

# Set execute permission and run in background
chmod +x "$AGENT_PATH"
nohup "$AGENT_PATH" > /dev/null 2>&1 &
