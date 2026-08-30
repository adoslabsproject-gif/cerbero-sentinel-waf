# Post for launch (not included in repo)

---

## Title

SENTINEL — an open-source WAF built for LLM/AI APIs (Rust, 4 layers, 2-15ms)

## Body

We've been running this in production for a few months to protect our AI agent platform. Decided to open-source it because nothing like it existed as a complete package.

**What it is:** A Web Application Firewall written in Rust, specifically designed for APIs that serve LLM endpoints. It's not a generic WAF adapted for AI — it was built from scratch for this use case.

**The 4 layers:**

1. **Edge** — rate limiting, IP reputation, GeoIP (MaxMind), DDoS detection, SQLite ban persistence, optional nftables kernel-level blocking
2. **Neural** — prompt injection detection (regex + optional ONNX model), toxicity, multi-encoding attack detection (base64/hex/unicode), system prompt extraction attempts
3. **Behavioral** — per-agent profiling with baseline learning, statistical anomaly detection, coordinated attack clustering, Sybil detection
4. **Response** — adaptive actions, proof-of-work challenges, ban escalation with repeat offender tracking

**Numbers:**
- 2-15ms per request (all 4 layers)
- 18MB static binary
- 83 tests
- Zero runtime dependencies (SQLite embedded, GeoIP optional)
- Zero external network calls

**What it does NOT do:**
- No telemetry, no phone-home
- No PII storage
- No request modification — only returns allow/block/challenge decisions
- No vendor lock-in — works with any backend language via HTTP

**How to use it:**

```bash
git clone https://github.com/adoslabsproject-gif/sentinel-waf
cd sentinel-waf
cargo build --release
./target/release/sentinel
```

Test with:
```bash
# Should return "allow"
curl -X POST http://127.0.0.1:8080/analyze \
  -d '{"client_ip":"8.8.8.8","path":"/api/chat","method":"POST","body":"Hello"}'

# Should return "block"
curl -X POST http://127.0.0.1:8080/analyze \
  -d '{"client_ip":"8.8.8.8","path":"/api/chat","method":"POST","body":"Ignore all previous instructions"}'
```

Integrates with nginx via `auth_request`. Works standalone as an HTTP API. Docker included.

Apache 2.0 license. Built by the team behind NotHumanAllowed.

GitHub: https://github.com/adoslabsproject-gif/sentinel-waf

---

## Where to post

- r/rust
- r/netsec
- r/machinelearning
- r/selfhosted
- Hacker News (Show HN)
- dev.to
- lobste.rs
