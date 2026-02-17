# Roadmap

## v0.1.0 (current)
- Pattern-based prompt injection detection (45 patterns)
- PII detection and redaction (emails, phones, SSNs, credit cards, IPs)
- JSONL audit logging with retention and rotation
- Token bucket rate limiting with file-based persistence
- Configurable sensitivity levels (strict/balanced/permissive)
- Allowlist/blocklist support
- 43 tests, zero dependencies

## v0.2.0
- **Input normalization** — Unicode NFKC, whitespace/punctuation stripping, case folding before pattern matching (catches leetspeak, spacing evasions)
- **False positive tuning** — per-pattern suppression, context-aware exceptions for developer queries
- **Improved scoring** — decouple score from text length, better normalization
- **Pattern versioning** — track which ruleset version flagged each event
- Configurable pattern sets — load/swap rule packs for different use cases

## v0.5.0
- **Behavioral analysis** — track patterns across sessions, not just single inputs
- **Source reputation scoring** — build trust profiles per source over time (reputation-weighted detection)
- Alert aggregation — batch similar events instead of logging each individually
- Integration hooks — callbacks for custom handling of blocked/flagged content

## v1.0.0
- Production hardening based on real-world usage feedback
- Comprehensive evasion testing (encoding tricks, Unicode edge cases, semantic rephrasing)
- Performance benchmarks and optimization
- Full review cycle at production quality bar
