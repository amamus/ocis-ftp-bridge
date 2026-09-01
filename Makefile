.PHONY: build test lint clean

PKG := github.com/amamus/ocis-ftp-bridge
VERSION ?= dev
DATE := $(shell date +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X $(PKG)/pkg/version.Version=$(VERSION) -X $(PKG)/pkg/version.BuildDate=$(DATE)

build:
	@echo "Building ocis-ftp-bridge..."
	@CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o ocis-ftp-bridge ./cmd/ocis-ftp-bridge

unit-test:
	@echo "Running unit tests..."
	@go test ./...

integration-test:
	@echo "Running integration tests..."
	@go test -tags=integration ./...

clean:
	@echo "Cleaning up..."
	@rm -f ocis-ftp-bridge

lint:
	@echo "Running linter..."
	@gofmt -d .
	@go vet ./...

fmt:
	@echo "Formatting code..."
	@gofmt -w .

help:
	@echo "Available targets:"
	@echo "  build    - Build the ocis-ftp-bridge binary"
	@echo "  unit-test - Run unit tests"
	@echo "  integration-test - Run integration tests"
	@echo "  clean    - Clean up build artifacts"
	@echo "  lint     - Run linter and vet"
	@echo "  fmt      - Format code"
	@echo "  help     - Show this help"
