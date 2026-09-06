# ocis-ftp-bridge Dockerfile
#
# Multi-stage build for a production-ready container
# Build stage uses full Go toolchain, runtime stage is minimal

# ============================================================================
# Build stage
# ============================================================================
FROM golang:1.27-alpine AS builder

# Set build arguments
ARG APP_NAME=ocis-ftp-bridge
ARG BINARY_NAME=ocis-ftp-bridge
ARG VERSION=1.0.0-dev
ARG COMMIT_SHA=unknown
ARG BUILD_DATE=unknown

# Install build dependencies
RUN apk add --no-cache git

# Set up working directory
WORKDIR /build

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with version information
RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-s -w \
		-X main.Version=${VERSION} \
		-X main.CommitSHA=${COMMIT_SHA} \
		-X main.BuildDate=${BUILD_DATE}" \
	-o /build/${BINARY_NAME} \
	./cmd/${APP_NAME}

# ============================================================================
# Runtime stage
# ============================================================================
FROM alpine:3.20 AS runtime

# Set labels for container metadata
LABEL org.opencontainers.image.title="ocis-ftp-bridge" \
	org.opencontainers.image.description="FTP to oCIS bridge service" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${COMMIT_SHA}" \
	org.opencontainers.image.created="${BUILD_DATE}" \
	org.opencontainers.image.source="https://github.com/amamus/ocis-ftp-bridge" \
	org.opencontainers.image.licenses="Apache-2.0" \
	org.opencontainers.image.vendor="amamus" \
	maintainer="amamus"

# Create non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set up directories with proper permissions
RUN mkdir -p /app/bin /app/config /app/spool /app/logs && \
	chown -R appuser:appgroup /app && \
	chmod -R 750 /app && \
	# Spool directory needs write permissions
	chmod 770 /app/spool

# Copy binary from build stage
COPY --from=builder /build/${BINARY_NAME} /app/bin/${BINARY_NAME}

# Copy default configuration (optional - can be mounted at runtime)
COPY --from=builder /build/config.yaml /app/config/config.yaml.default

# Set working directory
WORKDIR /app

# Switch to non-root user
USER appuser

# Set environment variables
ENV APP_NAME=${APP_NAME} \
	APP_VERSION=${VERSION} \
	CONFIG_FILE=/app/config/config.yaml

# Expose ports
EXPOSE 2121/tcp  # FTP control port
EXPOSE 40000-50000/tcp  # FTP passive port range (example)
EXPOSE 9200/tcp  # HTTP operations/health port

# Set entrypoint
ENTRYPOINT ["/app/bin/ocis-ftp-bridge"]

# Set default command (can be overridden)
CMD ["-config", "/app/config/config.yaml"]

# Health check - check that the HTTP health endpoint responds
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
	CMD wget --quiet --tries=1 --spider http://localhost:9200/healthz || exit 1

# Volumes for persistent data
VOLUME ["/app/spool", "/app/config", "/app/logs"]