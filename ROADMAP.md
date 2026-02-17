# Roadmap

## v0.1.0 (current)
- Pattern-based prompt injection detection
- PII detection and redaction (emails, phones, SSNs, credit cards, IPs)
- JSONL audit logging with retention and rotation
- Token bucket rate limiting with file-based persistence
- Configurable sensitivity levels (strict/balanced/permissive)
- Allowlist/blocklist support
- 43 tests, zero dependencies

## v0.2.0
- Configurable pattern sets — load/swap rule packs for different use cases
- False positive tuning — per-pattern suppression and threshold adjustment
- Pattern versioning — track which ruleset version flagged each event
- Improved scoring — reduce sensitivity to text length, better normalization

## v0.5.0
- Behavioral analysis — track patterns across sessions, not just single inputs
- Source reputation scoring — build trust profiles per source over time
- Alert aggregation — batch similar events instead of logging each individually
- Integration hooks — callbacks for custom handling of blocked/flagged content

## v1.0.0
- Production hardening based on real-world usage feedback
- Performance benchmarks and optimization
- Comprehensive evasion testing (encoding tricks, Unicode normalization, etc.)
- Full review cycle (Claude + GPT-5.2) at production quality bar
