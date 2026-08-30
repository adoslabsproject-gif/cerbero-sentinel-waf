# What is SENTINEL

SENTINEL is a Web Application Firewall built in Rust, designed specifically for APIs that serve LLM/AI endpoints.

It sits between your reverse proxy (nginx, Traefik, Caddy) and your application. Every incoming request passes through 4 analysis layers before reaching your backend. The decision (allow, block, challenge, rate-limit) takes 2-15ms.

## What it does

**Layer 1 — Edge Shield** (< 1ms)
- Sliding-window rate limiting per IP
- IP reputation scoring (known attackers, Tor exits, proxies, scanners)
- GeoIP country + ASN lookup (MaxMind GeoLite2)
- Datacenter detection (AWS, GCP, Azure, Hetzner, OVH, DigitalOcean, etc.)
- DDoS pattern detection (volumetric, slowloris, application-layer)
- IP ban persistence with SQLite (survives restarts)
- Optional nftables integration (kernel-level packet dropping)

**Layer 2 — Neural Defense** (< 5ms)
- Prompt injection detection (regex patterns + optional ONNX DeBERTa model)
- Toxicity detection (hate speech, threats, harassment)
- Multi-layer encoding attack detection (base64, hex, unicode, URL encoding, HTML entities, mixed)
- System prompt extraction attempt detection
- LLM output safety analysis (detects compromised model responses)
- Suspicious pattern matching with confidence scoring

**Layer 3 — Behavioral Analysis** (< 3ms)
- Per-agent behavioral baseline (learns normal request patterns)
- Statistical anomaly detection (z-score deviation from baseline)
- Coordinated attack clustering (multiple IPs acting together)
- Sybil attack detection (many identities, same behavior)
- Distributed probing detection
- Session fingerprinting and tracking

**Layer 4 — Response** (< 1ms)
- Adaptive response selection based on combined risk score
- IP banning with configurable duration and automatic expiry
- Proof-of-work challenges (CPU cost for suspicious clients)
- Interactive challenges (CAPTCHA-like verification)
- Threat escalation with severity tracking
- Ban count tracking (repeat offenders get longer bans)

## What it includes

- 36 Rust source files, ~9,200 lines
- 83 unit tests
- HTTP server (Axum) with REST API
- Prometheus metrics endpoint
- JSON metrics endpoint
- Health check endpoint
- nginx auth_request integration example
- Docker + docker-compose files
- Log analyzer CLI tool (bash + jq)
- GeoIP database download script

## What it requires

- Rust toolchain (build only)
- Nothing else at runtime — single static binary

Optional:
- MaxMind GeoLite2 databases (free, requires registration) for country/ASN detection
- ONNX models for ML-based detection (works without them using pattern matching)
- nftables for kernel-level ban enforcement (requires root on Linux)

## What it does NOT do

- Does not phone home or make any external network calls
- Does not store request bodies or PII
- Does not require a database server (SQLite is embedded)
- Does not require root (except for optional nftables)
- Does not modify or proxy requests — it only returns allow/block decisions
