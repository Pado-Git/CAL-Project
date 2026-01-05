# Build all CAL Hands Docker images (Windows PowerShell)

Write-Host "Building CAL Security Tools Images..." -ForegroundColor Green

Write-Host "1. Building security-tools (all-in-one)..."
docker build -t cal/security-tools:latest .\security-tools

Write-Host "2. Building nmap (lightweight)..."
docker build -t cal/nmap:latest .\nmap

Write-Host "3. Building curl (HTTP client)..."
docker build -t cal/curl:latest .\curl

Write-Host "4. Building xss-verifier (Headless browser verification)..."
docker build -t cal/xss-verifier:latest .\xss-verifier

Write-Host "✅ All images built successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Available images:"
docker images | Select-String "cal"
