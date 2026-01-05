# XSS Verification Docker Image with Playwright
FROM mcr.microsoft.com/playwright:v1.40.0-jammy

WORKDIR /app

# Copy verification script
COPY verify_xss.js /app/verify_xss.js
COPY package.json /app/package.json

# Install dependencies
RUN npm install

# Run verification script
ENTRYPOINT ["node", "/app/verify_xss.js"]
