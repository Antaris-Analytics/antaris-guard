# Changelog

All notable changes to antaris-guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),

## [0.5.0] - 2026-02-16

### Added (Behavioral Analysis)
- **ReputationTracker**: Per-source trust profiles that evolve over time
  - Trust increases with safe interactions, decreases with threats
  - Inactivity decay (trust drifts back to baseline over time)
  - Threshold adjustment — trusted sources get more lenient detection
  - High-risk source identification
  - File-based persistence with atomic writes
- **BehaviorAnalyzer**: Cross-session pattern detection
  - **Burst detection**: Rapid-fire suspicious/blocked requests in time window
  - **Escalation detection**: Sources that start safe and gradually test boundaries
  - **Probe sequence detection**: Systematic testing of different attack vectors
  - Per-source interaction history with configurable window size
  - File-based persistence with atomic writes
- 18 new tests (10 reputation + 8 behavior), 71 total

## [0.2.0] - 2026-02-16

### Added
- **Input normalization** — Unicode NFKC, zero-width char removal, spaced-character collapsing, leetspeak decoding
- **Evasion resistance** — patterns run against both original and normalized text
- `normalize()` and `normalize_light()` exported for standalone use
- 10 new tests (normalization, false positive reduction, score independence), 53 total

### Changed
- **Score decoupled from text length** — threat score now based on match count and severity, not inversely proportional to input length. Padding attacks no longer reduce scores.
- **Reduced false positives** on developer queries — "debug mode" / "admin mode" / "run this code" / "eval()" patterns now require imperative context instead of matching mentions in conversation
- **"what can't you do"** pattern uses negative lookahead to avoid triggering on "what can't you do with Python?"
- Command execution patterns: "run this code/script" downgraded from BLOCKED to SUSPICIOUS (reduces false positives while still flagging)
- 47 injection patterns (up from 45)

### Fixed
- `save_config()` crash on plain filenames in PromptGuard and ContentFilter
- RateLimiter silent persistence failure on plain filenames
- `ip_address` detection now enabled by default (was documented but disabled)
- RateLimiter: `os.rename` → `os.replace` (cross-platform atomic) + fsync before rename
- AuditLogger: flush after each JSONL write
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Enhanced Unicode and multi-language injection pattern detection
- Performance optimizations for batch processing
- Integration examples for more web frameworks
- Custom pattern validation and testing tools
- Machine learning model integration (optional)

## [0.1.0] - 2026-02-16

### Added
- **PromptGuard**: Pattern-based prompt injection detection
  - 40+ built-in injection patterns covering system overrides, jailbreaks, code injection
  - Configurable sensitivity levels (strict, balanced, permissive)
  - Allowlist/blocklist support
  - Custom pattern support with threat level classification
  - File-based JSON configuration
  - Threat scoring with 0.0-1.0 scale

- **ContentFilter**: PII detection and content filtering
  - Email, phone, SSN, credit card detection
  - API key and credential pattern detection
  - Configurable redaction masks
  - Output sanitization (HTML, JavaScript, SQL injection patterns)
  - Per-PII-type enable/disable controls
  - Custom pattern support

- **AuditLogger**: Security event logging
  - Structured JSON Lines logging format
  - Configurable retention policies (default 30 days)
  - Automatic log rotation by size and date
  - Event querying with filters (time range, type, severity, source)
  - Summary statistics and reporting
  - Built-in cleanup for old log files

- **RateLimiter**: Token bucket rate limiting
  - Per-source rate limiting with configurable RPS and burst
  - File-based state persistence across restarts
  - Thread-safe operations with RLock
  - Automatic cleanup of old bucket states
  - Per-source configuration overrides
  - Bucket reset and status inspection

- **Core Features**:
  - Zero external dependencies (Python stdlib only)
  - Thread-safe operations
  - Comprehensive error handling with graceful degradation
  - 43 tests
  - Type hints throughout codebase
  - Consistent API design across components

### Technical Details
- **Minimum Python version**: 3.9+
- **Dependencies**: None (zero dependencies)
- **License**: Apache 2.0
- **Package size**: ~50KB
- **Memory footprint**: ~5MB base + ~100 bytes per rate limit bucket
- **Performance**: 
  - Prompt analysis: ~50,000 texts/sec
  - PII detection: ~30,000 texts/sec  
  - Rate limit checks: ~100,000 ops/sec

### Pattern Coverage
- **System prompt overrides**: "ignore all instructions", "forget previous"
- **Role confusion**: "act as", "pretend you are", "roleplay"
- **Developer modes**: "developer mode", "debug mode", "god mode"
- **Jailbreak attempts**: "DAN mode", "break free", "escape constraints"
- **Command injection**: "execute", "run", "eval()", "exec()"
- **Information extraction**: "show system prompt", "reveal instructions"
- **Social engineering**: "urgent emergency", "my boss said"
- **Code injection**: `<script>`, `javascript:`, `onclick=`
- **SQL injection**: `UNION SELECT`, `DROP TABLE`, `--`, `#`
- **Template injection**: `{{}}`, `${}`, `<%>`
- **Encoding attempts**: base64, Unicode escapes, URL encoding

### PII Detection
- **Email addresses**: RFC-compliant regex matching
- **Phone numbers**: US formats including (555) 123-4567, 555-123-4567, +1-555-123-4567
- **SSNs**: 123-45-6789 and 123 45 6789 formats
- **Credit cards**: Visa, Mastercard, Amex, Discover patterns with basic validation
- **IP addresses**: IPv4 dotted decimal notation
- **Credentials**: password=, api_key=, token=, secret= patterns

### Configuration
- **JSON-based configuration** files for all components
- **Sensitivity levels**: strict (high sensitivity), balanced (default), permissive (lower sensitivity)
- **Custom patterns**: Regex patterns with threat level assignment
- **Allowlist/blocklist**: Text-based overrides for specific content
- **Redaction masks**: Customizable replacement strings per PII type
- **Rate limits**: Per-source RPS and burst configuration
- **Audit retention**: Configurable log retention periods

### API Design
- **Consistent result objects**: All components return structured dataclasses
- **Boolean convenience methods**: `.is_safe()`, `.is_blocked()`, etc.
- **Stats and monitoring**: `.get_stats()` methods for operational visibility
- **Error handling**: Graceful degradation, no exceptions for malformed input
- **Thread safety**: All components safe for concurrent use

### Testing
- **43 tests** covering functionality and edge cases
- **Real injection patterns** tested against actual attack strings
- **Integration tests** demonstrating multi-component workflows
- **Performance benchmarks** for all major operations
- **Configuration persistence** testing across component restarts
- **Edge case handling**: empty input, malformed data, file I/O errors

---

## Version History

- **v0.1.0** - Initial release with full feature set
- **v0.0.1** - Development version (not released)

## Breaking Changes

None in this initial release.

Future breaking changes will be clearly documented here with migration guides.

## Migration Guide

This is the initial release, no migration required.

## Security Disclosures

If you discover a security vulnerability in antaris-guard, please report it to:
- **Email**: security@antarisanalytics.ai
- **Subject**: "antaris-guard Security Issue"

Please do not report security issues in public GitHub issues.

## Contributors

- Antaris Analytics Team - Initial development and architecture
- Community contributors welcome - see CONTRIBUTING.md