# =============================================================================
# Stage 1: Build, lint, and test
# =============================================================================
FROM rust:1.89.0-trixie AS builder

# Install clippy component
RUN rustup component add clippy

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies (for caching)
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy the actual source code
COPY src ./src

# Touch main.rs to invalidate the dummy build
RUN touch src/main.rs

# Run clippy - fail on warnings
RUN cargo clippy --release -- -D warnings

# Run tests
RUN cargo test --release

# Build release binary
RUN cargo build --release

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (the app will need elevated capabilities at runtime)
RUN useradd -r -s /bin/false k8stun

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/k8stun /usr/local/bin/k8stun

# Note: This application requires NET_ADMIN capability and access to /dev/net/tun
# Run with: docker run --cap-add=NET_ADMIN --device=/dev/net/tun ...

ENTRYPOINT ["/usr/local/bin/k8stun"]

