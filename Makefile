.PHONY: build test lint fmt clean install help

# Binary name
BINARY=smcp

# Build variables
VERSION ?= dev
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X github.com/security-mcp/mcp-client/internal/cli.Version=$(VERSION) \
           -X github.com/security-mcp/mcp-client/internal/cli.GitCommit=$(GIT_COMMIT) \
           -X github.com/security-mcp/mcp-client/internal/cli.BuildDate=$(BUILD_DATE)

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build the mcp binary
	@echo "Building $(BINARY)..."
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/smcp

test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests and show coverage
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint: ## Run linters
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	elif [ -f $(HOME)/go/bin/golangci-lint ]; then \
		$(HOME)/go/bin/golangci-lint run; \
	else \
		echo "golangci-lint not found. Install it from https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(BINARY)
	rm -f coverage.out coverage.html
	rm -rf .out/
	go clean

install: build ## Install the binary to $GOPATH/bin
	@echo "Installing $(BINARY)..."
	go install -ldflags "$(LDFLAGS)" ./cmd/smcp

tidy: ## Run go mod tidy
	@echo "Running go mod tidy..."
	go mod tidy

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download

all: fmt lint test build ## Run fmt, lint, test, and build

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t mcp-client:latest .

docker-run: docker-build ## Run mcp in Docker container
	@echo "Running mcp in Docker..."
	docker run --rm mcp-client:latest --version

release-snapshot: ## Build release snapshot (requires goreleaser)
	@echo "Building release snapshot..."
	@if command -v goreleaser >/dev/null 2>&1; then \
		goreleaser release --snapshot --clean; \
	else \
		echo "goreleaser not found. Install from https://goreleaser.com/install/"; \
		exit 1; \
	fi
