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

Sprint 4 — Policy composition DSL:

    from antaris_guard import (
        rate_limit_policy, content_filter_policy, cost_cap_policy,
        PromptGuard,
    )

    policy = rate_limit_policy(10, per="minute") & content_filter_policy("pii")
    guard = PromptGuard(policy=policy)
"""

__version__ = "2.2.0"

# MCP server integration (optional — requires `pip install mcp`)
try:
    from .mcp_server import create_server as create_mcp_server, MCP_AVAILABLE
    __all_mcp__ = ["create_mcp_server", "MCP_AVAILABLE"]
except Exception:  # pragma: no cover — only fails if antaris_guard itself is broken
    create_mcp_server = None  # type: ignore[assignment]
    MCP_AVAILABLE = False
    __all_mcp__ = []

# Core
from .guard import PromptGuard, GuardResult, SensitivityLevel
from .content import ContentFilter, FilterResult
from .audit import AuditLogger, AuditEvent
from .rate_limit import RateLimiter, RateLimitResult, BucketState

# Behavioral analysis
from .reputation import ReputationTracker, ReputationProfile
from .behavior import BehaviorAnalyzer, BehaviorAlert

# Conversation-level guard (Sprint 10)
from .conversation import ConversationGuard, ConversationResult

# Compliance templates (Sprint 10)
from .compliance import ComplianceTemplate

# Stateful conversation policies (Sprint 2.5)
from .conversation_state import ConversationStateStore, ConversationState, MessageRecord
from .policies import (
    StatefulPolicy,
    StatefulPolicyResult,
    EscalationPolicy,
    BurstPolicy,
    BoundaryTestPolicy,
    ConversationCostCapPolicy,
    CompositeStatefulPolicy,
)

# Policy composition (Sprint 4)
from .policy import (
    Policy,
    BasePolicy,
    PolicyResult,
    RateLimitPolicy,
    ContentFilterPolicy,
    CostCapPolicy,
    CompositePolicy,
    PolicyRegistry,
    POLICY_VERSION,
    rate_limit_policy,
    content_filter_policy,
    cost_cap_policy,
)

# Utilities
from .patterns import (
    ThreatLevel, PatternMatcher, PATTERN_VERSION,
    PROMPT_INJECTION_PATTERNS, AGGRESSIVE_INJECTION_PATTERNS, PII_PATTERNS,
    MULTILINGUAL_INJECTION_PATTERNS,
)
from .normalizer import normalize, normalize_light
from .utils import atomic_write_json

__all__ = [
    # Core
    "PromptGuard",
    "ContentFilter",
    "AuditLogger",
    "RateLimiter",
    "GuardResult",
    "FilterResult",
    "AuditEvent",
    "RateLimitResult",
    "BucketState",
    # Behavioral
    "ReputationTracker",
    "ReputationProfile",
    "BehaviorAnalyzer",
    "BehaviorAlert",
    # Policy composition (Sprint 4)
    "Policy",
    "BasePolicy",
    "PolicyResult",
    "RateLimitPolicy",
    "ContentFilterPolicy",
    "CostCapPolicy",
    "CompositePolicy",
    "PolicyRegistry",
    "POLICY_VERSION",
    "rate_limit_policy",
    "content_filter_policy",
    "cost_cap_policy",
    # Conversation guard (Sprint 10)
    "ConversationGuard",
    "ConversationResult",
    # Compliance templates (Sprint 10)
    "ComplianceTemplate",
    # Stateful conversation policies (Sprint 2.5)
    "ConversationStateStore",
    "ConversationState",
    "MessageRecord",
    "StatefulPolicy",
    "StatefulPolicyResult",
    "EscalationPolicy",
    "BurstPolicy",
    "BoundaryTestPolicy",
    "ConversationCostCapPolicy",
    "CompositeStatefulPolicy",
    # Patterns / utilities
    "ThreatLevel",
    "SensitivityLevel",
    "PatternMatcher",
    "PATTERN_VERSION",
    "PROMPT_INJECTION_PATTERNS",
    "AGGRESSIVE_INJECTION_PATTERNS",
    "PII_PATTERNS",
    "MULTILINGUAL_INJECTION_PATTERNS",
    "normalize",
    "normalize_light",
    # MCP server (optional — requires mcp package)
    "create_mcp_server",
    "MCP_AVAILABLE",
]
