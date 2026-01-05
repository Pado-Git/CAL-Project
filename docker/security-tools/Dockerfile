# Security Tools Container for CAL Hands
FROM alpine:latest

# Install common security tools
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    curl \
    wget \
    bind-tools \
    net-tools \
    ca-certificates \
    python3 \
    py3-pip

# Install additional Python-based tools (optional)
# RUN pip3 install --no-cache-dir requests beautifulsoup4

WORKDIR /scan

# Default command
CMD ["/bin/sh"]
