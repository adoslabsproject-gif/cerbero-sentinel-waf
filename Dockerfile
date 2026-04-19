# SENTINEL WAF — Multi-stage Docker build
# Stage 1: Build the Rust binary
FROM rust:1.82-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --bin sentinel-server

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/sentinel-server /usr/local/bin/sentinel-server

# Create models directory (mount your ONNX models here)
RUN mkdir -p /opt/sentinel/models

ENV SENTINEL_PORT=8080
ENV SENTINEL_LOG_LEVEL=warn
ENV SENTINEL_MODELS_PATH=/opt/sentinel/models

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["sentinel-server"]
