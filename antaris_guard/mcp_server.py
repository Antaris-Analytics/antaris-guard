"""
Antaris Guard MCP Server

Exposes antaris-guard as MCP tools for any MCP-enabled agent or Claude integration.

Tools:
  - check_safety: Analyze text for prompt injection, PII, and policy violations
  - redact_pii: Detect and redact PII from text
  - get_security_posture: Get current security posture score

Usage:
    python -m antaris_guard.mcp_server
    # or
    from antaris_guard.mcp_server import create_server, run_server

MCP library (mcp>=1.0.0) must be installed separately:
    pip install mcp
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Graceful degradation when mcp is not installed
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:  # pragma: no cover
    MCP_AVAILABLE = False
    FastMCP = None  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Antaris Guard imports (always available — zero-dependency package)
# ---------------------------------------------------------------------------
from .guard import PromptGuard, SensitivityLevel
from .content import ContentFilter

# ---------------------------------------------------------------------------
# Singleton guard/filter instances used by the tools.
# These are created once per process so state (stats, posture) accumulates
# naturally across multiple tool calls in the same session.
# ---------------------------------------------------------------------------
_guard: PromptGuard | None = None
_filter: ContentFilter | None = None


def _get_guard() -> PromptGuard:
    """Return (or lazily create) the shared PromptGuard instance."""
    global _guard
    if _guard is None:
        _guard = PromptGuard(sensitivity=SensitivityLevel.BALANCED)
    return _guard


def _get_filter() -> ContentFilter:
    """Return (or lazily create) the shared ContentFilter instance."""
    global _filter
    if _filter is None:
        _filter = ContentFilter(strict_validation=True)
    return _filter


# ---------------------------------------------------------------------------
# Tool implementation helpers (pure functions — easy to unit-test)
# ---------------------------------------------------------------------------

_VALID_SENSITIVITIES = {
    SensitivityLevel.STRICT,
    SensitivityLevel.BALANCED,
    SensitivityLevel.PERMISSIVE,
}


def _check_safety_impl(text: str, sensitivity: str = "balanced") -> Dict[str, Any]:
    """
    Core implementation for the check_safety tool.

    Args:
        text:        The text to analyze for safety threats.
        sensitivity: Detection sensitivity — "strict", "balanced" (default), or "permissive".

    Returns:
        dict with keys:
            safe (bool)           — True when the input is considered safe.
            blocked (bool)        — True when the input should be rejected.
            threat_level (str)    — "safe", "suspicious", or "blocked".
            score (float)         — Threat score 0.0 (safe) to 1.0 (malicious).
            matches (list)        — Pattern-match details.
            message (str)         — Human-readable verdict.
    """
    if sensitivity not in _VALID_SENSITIVITIES:
        sensitivity = SensitivityLevel.BALANCED

    guard = PromptGuard(sensitivity=sensitivity)
    result = guard.analyze(text)

    return {
        "safe": result.is_safe,
        "blocked": result.is_blocked,
        "threat_level": result.threat_level.value,
        "score": round(result.score, 4),
        "matches": result.matches,
        "message": result.message,
    }


def _redact_pii_impl(text: str, strict_validation: bool = True) -> Dict[str, Any]:
    """
    Core implementation for the redact_pii tool.

    Args:
        text:              Text that may contain PII.
        strict_validation: Apply Luhn check for credit cards and range-check
                           for IP addresses to reduce false positives (default True).

    Returns:
        dict with keys:
            redacted_text (str)     — Text with PII replaced by type-specific tags.
            pii_types_found (list)  — PII categories detected (e.g. ["email", "ssn"]).
            detection_count (int)   — Total number of PII instances detected.
    """
    cf = ContentFilter(strict_validation=strict_validation)
    result = cf.filter_content(text, sanitize=False)

    pii_types_found = sorted({d["type"] for d in result.detections})

    return {
        "redacted_text": result.filtered_text,
        "pii_types_found": pii_types_found,
        "detection_count": result.redaction_count,
    }


def _get_security_posture_impl() -> Dict[str, Any]:
    """
    Core implementation for the get_security_posture tool.

    Uses the shared PromptGuard instance so the posture reflects any
    accumulated analysis history for this server session.

    Returns:
        dict with keys:
            score (float)            — Posture score 0.0 (insecure) to 1.0 (maximal).
            level (str)              — "low", "medium", "high", or "critical".
            components (dict)        — Per-component scores.
            recommendations (list)   — Actionable improvement suggestions.
    """
    guard = _get_guard()
    return guard.security_posture_score()


# ---------------------------------------------------------------------------
# MCP server factory
# ---------------------------------------------------------------------------

def create_server(name: str = "antaris-guard") -> "FastMCP":  # type: ignore[return]
    """
    Create and return a configured FastMCP server instance.

    The server exposes three tools:
      • check_safety         — Detect prompt injection and policy violations
      • redact_pii           — Detect and redact PII from text
      • get_security_posture — Return the current security posture score

    Args:
        name: Server name shown to MCP clients (default "antaris-guard").

    Raises:
        ImportError: If the ``mcp`` package is not installed.

    Example::

        from antaris_guard.mcp_server import create_server
        server = create_server()
        server.run()  # stdio transport by default
    """
    if not MCP_AVAILABLE:
        raise ImportError(
            "The 'mcp' package is required to use the MCP server.\n"
            "Install it with: pip install mcp"
        )

    mcp = FastMCP(
        name,
        instructions=(
            "Antaris Guard provides AI safety checking tools. "
            "Use check_safety to detect prompt injection, redact_pii to remove "
            "sensitive data, and get_security_posture to assess configuration strength."
        ),
    )

    # ------------------------------------------------------------------
    # Tool: check_safety
    # ------------------------------------------------------------------
    @mcp.tool(
        name="check_safety",
        description=(
            "Analyze text for prompt injection attacks, jailbreak attempts, and policy violations. "
            "Returns a safety verdict with threat level, score, and matched patterns. "
            "Use sensitivity='strict' for high-security environments, "
            "'permissive' for low-noise contexts, 'balanced' (default) for everyday use."
        ),
    )
    def check_safety(
        text: str,
        sensitivity: str = "balanced",
    ) -> Dict[str, Any]:
        """
        Analyze text for safety threats.

        Args:
            text:        The text to analyze.
            sensitivity: "strict", "balanced" (default), or "permissive".

        Returns:
            {safe, blocked, threat_level, score, matches, message}
        """
        return _check_safety_impl(text, sensitivity)

    # ------------------------------------------------------------------
    # Tool: redact_pii
    # ------------------------------------------------------------------
    @mcp.tool(
        name="redact_pii",
        description=(
            "Detect and redact personally identifiable information (PII) from text. "
            "Handles emails, phone numbers, SSNs, credit card numbers, IP addresses, "
            "API keys, and credential patterns. "
            "Returns the redacted text and a summary of what was found."
        ),
    )
    def redact_pii(
        text: str,
        strict_validation: bool = True,
    ) -> Dict[str, Any]:
        """
        Detect and redact PII from text.

        Args:
            text:              Text that may contain PII.
            strict_validation: If True (default), apply Luhn and IP range checks
                               to reduce false positives.

        Returns:
            {redacted_text, pii_types_found, detection_count}
        """
        return _redact_pii_impl(text, strict_validation)

    # ------------------------------------------------------------------
    # Tool: get_security_posture
    # ------------------------------------------------------------------
    @mcp.tool(
        name="get_security_posture",
        description=(
            "Return the current security posture score for the Antaris Guard instance. "
            "Evaluates rate limiting, content filtering, pattern coverage, sensitivity, "
            "and behavioral analysis hooks. Score ranges from 0.0 (insecure) to 1.0 (maximal). "
            "Includes actionable recommendations for improvement."
        ),
    )
    def get_security_posture() -> Dict[str, Any]:
        """
        Get the current security posture score.

        Returns:
            {score, level, components, recommendations}
        """
        return _get_security_posture_impl()

    return mcp


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------

def run_server(transport: str = "stdio") -> None:
    """
    Create and run the Antaris Guard MCP server.

    Args:
        transport: MCP transport — "stdio" (default), "sse", or "streamable-http".

    Raises:
        ImportError: If the ``mcp`` package is not installed.
    """
    server = create_server()
    server.run(transport=transport)  # type: ignore[arg-type]


def main() -> None:
    """
    CLI entry point for ``antaris-guard-mcp``.

    Usage:
        antaris-guard-mcp                  # stdio transport (default)
        antaris-guard-mcp --transport sse  # SSE transport

    Typically invoked by Claude Desktop or another MCP host via subprocess.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="antaris-guard-mcp",
        description="Run the Antaris Guard MCP server.",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport to use (default: stdio).",
    )
    args = parser.parse_args()

    if not MCP_AVAILABLE:
        print(
            "ERROR: The 'mcp' package is required.\n"
            "Install it with: pip install mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    run_server(transport=args.transport)


# ---------------------------------------------------------------------------
# __main__ support: python -m antaris_guard.mcp_server
# ---------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    main()
