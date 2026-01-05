# Curl HTTP Client Container
FROM alpine:latest

RUN apk add --no-cache curl ca-certificates

WORKDIR /scan

# No CMD or ENTRYPOINT - let executor provide full command
