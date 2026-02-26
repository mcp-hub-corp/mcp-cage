# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN make build

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 mcp && \
    adduser -D -u 1000 -G mcp mcp

# Create cache directory
RUN mkdir -p /home/mcp/.smcp/cache && \
    chown -R mcp:mcp /home/mcp/.smcp

# Copy binary from builder
COPY --from=builder /build/smcp /usr/local/bin/smcp

# Switch to non-root user
USER mcp
WORKDIR /home/mcp

# Set default registry
ENV MCP_REGISTRY_URL=https://registry.mcp-hub.info
ENV MCP_CACHE_DIR=/home/mcp/.smcp/cache

ENTRYPOINT ["/usr/local/bin/smcp"]
CMD ["--help"]
