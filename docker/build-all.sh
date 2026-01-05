#!/bin/bash

# Build all cal Hands Docker images

echo "Building cal Security Tools Images..."

echo "1. Building security-tools (all-in-one)..."
docker build -t cal/security-tools:latest ./security-tools

echo "2. Building nmap (lightweight)..."
docker build -t cal/nmap:latest ./nmap

echo "✅ All images built successfully!"
echo ""
echo "Available images:"
docker images | grep cal
