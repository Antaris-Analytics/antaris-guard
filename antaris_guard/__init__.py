"""
Antaris Guard — Security and prompt injection detection for AI agents.

Pattern-based threat detection, PII redaction, audit logging, and rate
limiting using only the Python standard library. Zero dependencies,
deterministic operations, transparent configuration.

Usage:
    from antaris_guard import PromptGuard, ContentFilter

    guard = PromptGuard()
    result = guard.analyze("user input here")
    if result.is_blocked:
        print(f"Blocked: {result.message}")
"""

__version__ = "0.5.0"

# Core
from .guard import PromptGuard, GuardResult, SensitivityLevel
from .content import ContentFilter, FilterResult
from .audit import AuditLogger, AuditEvent
from .rate_limit import RateLimiter, RateLimitResult, BucketState

# Behavioral analysis
from .reputation import ReputationTracker, ReputationProfile
from .behavior import BehaviorAnalyzer, BehaviorAlert

# Utilities
from .patterns import ThreatLevel, PatternMatcher
from .normalizer import normalize, normalize_light
from .utils import atomic_write_json

__all__ = [
    "PromptGuard",
    "ContentFilter",
    "AuditLogger",
    "RateLimiter",
    "GuardResult",
    "FilterResult",
    "AuditEvent",
    "RateLimitResult",
    "BucketState",
    "ReputationTracker",
    "ReputationProfile",
    "BehaviorAnalyzer",
    "BehaviorAlert",
    "ThreatLevel",
    "SensitivityLevel",
    "PatternMatcher",
    "normalize",
    "normalize_light",
]
