# Sovereign Trust SDK — PoC

Web attestation widget (reCAPTCHA replacement) using Privacy Pass with public metadata (RSAPBSSA).

## Current State

**All 26 tests pass. Full PoC implementation complete.**

| Package | Tests | Status |
|---------|-------|--------|
| `internal/rsapbssa` | 8 | ✅ RFC test vector round-trips pass (exact byte match) |
| `internal/challenge` | 5 | ✅ Parameter derivation + range validation |
| `internal/environment` | 5 | ✅ Probe pool integrity + validation logic |
| `pkg/api` | 4 | ✅ Metadata encode/decode |
| `cmd/server` | 4 | ✅ Full round-trip, replay protection, error cases |

**What's implemented:**

- `internal/rsapbssa/` — Full RSAPBSSA implementation: DerivePublicKey, DeriveKeyPair, Blind, BlindSign, Finalize, Verify, GenerateKey (safe primes). All 3 RFC test vectors pass with exact byte matching.
- `internal/challenge/` — Composite challenge: HashCash (CPU), Argon2id (memory), environment probes. Parameter derivation from HMAC-SHA256 seeds.
- `internal/temperature/` — In-memory abuse scoring (IP rate, subnet rate, token burn, probe consistency)
- `internal/environment/` — Server-side probe validation with 10-probe pool: webcrypto_timing, dom_computation, memory_allocation, canvas_timing, audio_latency, font_measurement, animation_frame, intersection_observer, webgl_query, performance_heap
- `pkg/api/` — Data contract types (challenge payloads, siteverify, trust metadata)
- `cmd/server/` — HTTP server: `/challenge`, `/verify`, `/siteverify`
- `widget/widget.js` — Vanilla JS client widget with HashCash solver, Argon2 WASM, 10 environment probe runners, RSAPBSSA blinding
- `widget/vendor/` — Vendored hash-wasm Argon2 WASM bundle with SRI integrity check
- `widget/widget.html` — Browser test page

## Architecture

```
Client Widget (JS + vendored Argon2 WASM)
    │
    ├── GET /challenge → server returns ChallengePayload + server public key
    │   (params derived from HMAC-SHA256 seed + temperature bucket)
    │   (3-5 probes selected from pool of 10 per challenge)
    │
    ├── Solves: HashCash PoW + Argon2 memory-hard + environment probes
    │   Client blinds a nonce with server's RSAPBSSA public key
    │
    ├── POST /verify → server verifies solutions, issues blind signature
    │   (trust metadata bound at challenge time: challenge class, temperature, device class, time bucket)
    │
    └── Client unblinds → token = sig || metadata || nonce
            │
            └── POST /siteverify → relying party verifies token, gets trust signals
```

## Running

```bash
# Run all tests
go test ./...

# Start the server (dev key pair, port 8080)
go run ./cmd/server/

# Open the browser test page
open http://localhost:8080/widget/widget.html
```

See `../Documentation/TESTING.md` for full testing guide including manual API tests.

## Key Design Decisions

- **RSAPBSSA over basic Blind RSA**: metadata enables graduated trust signals (challenge_class 0-3, temperature_bucket 0-3) — relying parties can set thresholds rather than binary pass/fail
- **Direct HMAC byte mapping for parameters**: the HMAC-SHA256 seed (server secret + nonce + timestamp + IP hash) is already uniformly random — parameters are derived by extracting bytes from the seed directly, no additional mixing layer needed
- **10-probe pool with randomized selection**: each challenge draws 3-5 probes from a pool of 10, so bot authors cannot precompute against a fixed set. Probes test platform behavior (WebCrypto timing, canvas pipeline, audio stack, layout engine, rAF jitter, IntersectionObserver, WebGL, heap size) — they fingerprint the software, not the user
- **Argon2id over pure HashCash**: GPU/ASIC resistance via memory-hardness; WASM required on client (pure JS is 10-50x slower)
- **Vendored WASM with SRI**: Argon2 WASM bundle served locally with SHA-384 integrity check — no runtime CDN dependency
- **Metadata bound at challenge time**: predicted metadata is stored when the challenge is issued and reused at signing time — no recomputation, no timing-dependent mismatches
- **Go backend**: strong crypto stdlib, good for token verification throughput

## PoC Limitations

Production features deferred from this PoC phase:
- Redis nonce store (uses in-memory)
- Persistent key storage (uses RFC test vector key pair)
- Minimum anonymity set enforcement (k=10 threshold per IETF draft §7.3)
- JA4 TLS fingerprinting in temperature system
- IP reputation lookup (datacenter/Tor/VPN detection)
- Per-site-key policy enforcement
- Domain verification for site keys
- Binary transparency log for WASM

See Technical Analysis v1.6 §3.3.5 and §3.5 for full production requirements.
