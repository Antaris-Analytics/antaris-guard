"""
Policy composition DSL for antaris-guard.

Provides boolean composition of security policies with & (AND) and | (OR)
operators, JSON serialization, versioning, and a policy registry.

Zero dependencies, pure Python, deterministic.

Usage::

    from antaris_guard.policy import rate_limit_policy, content_filter_policy

    policy = rate_limit_policy(10, per="minute") & content_filter_policy("pii")
    guard = PromptGuard(policy=policy)
    result = guard.analyze("some input")
"""
import json
import os
import time
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

POLICY_VERSION = "1.0"


# ---------------------------------------------------------------------------
# PolicyResult
# ---------------------------------------------------------------------------

class PolicyResult:
    """
    Result of a policy evaluation.

    Attributes:
        allowed:     True if the request passes this policy.
        reason:      Human-readable explanation.
        policy_name: Name of the policy that produced this result.
        confidence:  0.0–1.0; how certain the policy is about its decision.
    """

    __slots__ = ("allowed", "reason", "policy_name", "confidence")

    def __init__(self, allowed: bool, reason: str,
                 policy_name: str, confidence: float = 1.0):
        self.allowed = allowed
        self.reason = reason
        self.policy_name = policy_name
        self.confidence = max(0.0, min(1.0, confidence))

    def __repr__(self) -> str:  # pragma: no cover
        verdict = "ALLOW" if self.allowed else "DENY"
        return (f"PolicyResult({verdict}, policy={self.policy_name!r}, "
                f"reason={self.reason!r}, confidence={self.confidence:.2f})")


# ---------------------------------------------------------------------------
# BasePolicy
# ---------------------------------------------------------------------------

class BasePolicy(ABC):
    """
    Abstract base for all policies.

    Subclasses must implement :meth:`evaluate` and :meth:`to_dict`.

    Supports boolean composition via ``&`` (AND) and ``|`` (OR).
    """

    def __init__(self, name: str = "", version: str = POLICY_VERSION):
        self.version = version
        self.name = name or self.__class__.__name__

    # ------------------------------------------------------------------
    # Core interface
    # ------------------------------------------------------------------

    @abstractmethod
    def evaluate(self, text: str) -> PolicyResult:
        """Evaluate *text* against this policy and return a :class:`PolicyResult`."""
        ...

    # ------------------------------------------------------------------
    # Boolean composition operators
    # ------------------------------------------------------------------

    def __and__(self, other: "BasePolicy") -> "CompositePolicy":
        """Combine with AND: both policies must pass."""
        return CompositePolicy([self, other], operator="and")

    def __or__(self, other: "BasePolicy") -> "CompositePolicy":
        """Combine with OR: at least one policy must pass."""
        return CompositePolicy([self, other], operator="or")

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this policy to a plain dict.  Subclasses must override."""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement to_dict()"
        )

    def to_file(self, path: str) -> None:
        """Serialize this policy and write it to *path* as JSON (atomic write)."""
        from .utils import atomic_write_json
        atomic_write_json(path, self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BasePolicy":
        """
        Deserialize a policy from a plain dict.

        Dispatches on the ``"type"`` key.  Valid values:
        ``"rate_limit"``, ``"content_filter"``, ``"cost_cap"``,
        ``"composite"``.
        """
        policy_type = data.get("type", "")
        if policy_type == "rate_limit":
            return RateLimitPolicy(
                requests=data["requests"],
                per=data.get("per", "minute"),
                source_id=data.get("source_id", "_default"),
                name=data.get("name", ""),
                version=data.get("version", POLICY_VERSION),
            )
        elif policy_type == "content_filter":
            return ContentFilterPolicy(
                filter_type=data.get("filter", "all"),
                name=data.get("name", ""),
                version=data.get("version", POLICY_VERSION),
            )
        elif policy_type == "cost_cap":
            return CostCapPolicy(
                max_cost=data["max_cost"],
                per=data.get("per", "hour"),
                cost_per_request=data.get("cost_per_request", 0.001),
                name=data.get("name", ""),
                version=data.get("version", POLICY_VERSION),
            )
        elif policy_type == "composite":
            sub_policies = [BasePolicy.from_dict(p) for p in data.get("policies", [])]
            return CompositePolicy(
                policies=sub_policies,
                operator=data.get("operator", "and"),
                name=data.get("name", ""),
                version=data.get("version", POLICY_VERSION),
            )
        else:
            raise ValueError(f"Unknown policy type: {policy_type!r}")

    @classmethod
    def from_file(cls, path: str) -> "BasePolicy":
        """Load a policy from a JSON file at *path*."""
        with open(path, "r") as fh:
            data = json.load(fh)
        return cls.from_dict(data)


# Convenience alias — matches the spec's ``Policy.from_dict(…)`` usage
Policy = BasePolicy


# ---------------------------------------------------------------------------
# RateLimitPolicy
# ---------------------------------------------------------------------------

class RateLimitPolicy(BasePolicy):
    """
    Rate-limiting policy based on the token-bucket algorithm.

    Wraps :class:`~antaris_guard.rate_limit.RateLimiter`.

    Args:
        requests:  Maximum number of requests allowed in the window.
        per:       Window size — ``"minute"``, ``"hour"``, or ``"day"``.
        source_id: Bucket key (shared across evaluate calls by default).
        name:      Human-readable name (auto-generated if omitted).
        version:   Policy version string.
    """

    _PER_SECONDS: Dict[str, int] = {"minute": 60, "hour": 3600, "day": 86400}

    def __init__(self, requests: int, per: str = "minute",
                 source_id: str = "_default",
                 name: str = "", version: str = POLICY_VERSION):
        if per not in self._PER_SECONDS:
            raise ValueError(
                f"per must be one of {list(self._PER_SECONDS)}, got {per!r}"
            )
        self.requests = requests
        self.per = per
        self.source_id = source_id

        per_seconds = self._PER_SECONDS[per]
        self._rps: float = requests / per_seconds
        self._burst: int = requests

        self._limiter: Optional[Any] = None
        self._limiter_lock = threading.Lock()

        auto_name = name or f"rate_limit_{requests}_per_{per}"
        super().__init__(name=auto_name, version=version)

    # ------------------------------------------------------------------ #

    def _get_limiter(self):
        """Lazy-initialise the underlying :class:`RateLimiter`."""
        if self._limiter is None:
            with self._limiter_lock:
                if self._limiter is None:
                    import tempfile
                    from .rate_limit import RateLimiter
                    state_file = os.path.join(
                        tempfile.gettempdir(),
                        f"ag_rl_policy_{id(self)}.json",
                    )
                    self._limiter = RateLimiter(
                        state_file=state_file,
                        default_requests_per_second=self._rps,
                        default_burst_size=self._burst,
                    )
        return self._limiter

    def evaluate(self, text: str) -> PolicyResult:  # noqa: ARG002
        limiter = self._get_limiter()
        rl_result = limiter.check_rate_limit(self.source_id)
        if rl_result.allowed:
            return PolicyResult(
                allowed=True,
                reason=(
                    f"Rate limit OK "
                    f"({rl_result.remaining_tokens:.1f} tokens remaining)"
                ),
                policy_name=self.name,
                confidence=1.0,
            )
        return PolicyResult(
            allowed=False,
            reason=(
                f"Rate limit exceeded: {self.requests} requests per {self.per}. "
                f"Retry after {rl_result.retry_after:.1f}s."
            ),
            policy_name=self.name,
            confidence=1.0,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "rate_limit",
            "requests": self.requests,
            "per": self.per,
            "source_id": self.source_id,
            "name": self.name,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# ContentFilterPolicy
# ---------------------------------------------------------------------------

class ContentFilterPolicy(BasePolicy):
    """
    Content-based filtering policy.

    Supports four *filter_type* values:

    * ``"pii"``       — blocks if PII (email, SSN, credit card, …) is found
    * ``"injection"`` — blocks on prompt-injection patterns
    * ``"toxicity"``  — blocks on a keyword-based toxicity list (no ML)
    * ``"all"``       — all three checks above

    Args:
        filter_type: One of ``"pii"``, ``"injection"``, ``"toxicity"``, ``"all"``.
        name:        Human-readable name (auto-generated if omitted).
        version:     Policy version string.
    """

    _VALID_TYPES = frozenset({"pii", "toxicity", "injection", "all"})

    # Conservative toxicity keyword list — no ML, pure strings.
    _TOXICITY_KEYWORDS = [
        "bomb", "explosive", "detonate", "bioweapon", "chemical weapon",
        "nerve agent", "mass murder", "genocide", "child abuse",
        "csam", "child pornography",
    ]

    def __init__(self, filter_type: str = "all",
                 name: str = "", version: str = POLICY_VERSION):
        if filter_type not in self._VALID_TYPES:
            raise ValueError(
                f"filter_type must be one of {sorted(self._VALID_TYPES)}, "
                f"got {filter_type!r}"
            )
        self.filter_type = filter_type
        auto_name = name or f"content_filter_{filter_type}"
        super().__init__(name=auto_name, version=version)

        # Cache ContentFilter and PatternMatcher instances so they are not
        # re-created on every evaluate() call (performance fix).
        from .content import ContentFilter
        from .patterns import PatternMatcher
        self._content_filter = ContentFilter()
        self._pattern_matcher = PatternMatcher()

    def evaluate(self, text: str) -> PolicyResult:
        if not text or not text.strip():
            return PolicyResult(
                allowed=True, reason="Empty input",
                policy_name=self.name, confidence=1.0,
            )

        # --- PII check ---
        if self.filter_type in ("pii", "all"):
            if self._content_filter.has_pii(text):
                detected = self._content_filter.get_pii_types_found(text)
                return PolicyResult(
                    allowed=False,
                    reason=f"PII detected: {', '.join(sorted(detected))}",
                    policy_name=self.name,
                    confidence=0.9,
                )

        # --- Injection check ---
        if self.filter_type in ("injection", "all"):
            from .patterns import ThreatLevel
            matches = self._pattern_matcher.check_injection_patterns(text)
            blocked = [m for m in matches if m[1] == ThreatLevel.BLOCKED]
            if blocked:
                snippet = blocked[0][0][:60]
                return PolicyResult(
                    allowed=False,
                    reason=f"Injection pattern detected: {snippet!r}",
                    policy_name=self.name,
                    confidence=0.95,
                )

        # --- Toxicity check ---
        if self.filter_type in ("toxicity", "all"):
            text_lower = text.lower()
            for keyword in self._TOXICITY_KEYWORDS:
                if keyword in text_lower:
                    return PolicyResult(
                        allowed=False,
                        reason=f"Potentially harmful content: keyword {keyword!r}",
                        policy_name=self.name,
                        confidence=0.75,
                    )

        return PolicyResult(
            allowed=True,
            reason=f"Content filter ({self.filter_type}) passed",
            policy_name=self.name,
            confidence=1.0,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "content_filter",
            "filter": self.filter_type,
            "name": self.name,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# CostCapPolicy
# ---------------------------------------------------------------------------

class CostCapPolicy(BasePolicy):
    """
    Cost accumulation guard.

    Tracks per-request costs within a sliding time window and blocks when
    the cumulative cost would exceed *max_cost*.

    State is in-memory only (resets on process restart).  Thread-safe.

    Args:
        max_cost:          Maximum allowed spend in the window.
        per:               Window size — ``"minute"``, ``"hour"``, or ``"day"``.
        cost_per_request:  Cost charged for each ``evaluate`` call that passes.
        name:              Human-readable name (auto-generated if omitted).
        version:           Policy version string.
    """

    _PER_SECONDS: Dict[str, int] = {"minute": 60, "hour": 3600, "day": 86400}

    def __init__(self, max_cost: float, per: str = "hour",
                 cost_per_request: float = 0.001,
                 name: str = "", version: str = POLICY_VERSION):
        if per not in self._PER_SECONDS:
            raise ValueError(
                f"per must be one of {list(self._PER_SECONDS)}, got {per!r}"
            )
        self.max_cost = max_cost
        self.per = per
        self.cost_per_request = cost_per_request
        self._window_seconds: int = self._PER_SECONDS[per]

        # List of (timestamp, cost) tuples
        self._charges: List[Tuple[float, float]] = []
        self._lock = threading.Lock()

        auto_name = name or f"cost_cap_{max_cost}_per_{per}"
        super().__init__(name=auto_name, version=version)

    # ------------------------------------------------------------------ #

    def _prune(self) -> None:
        """Remove charges outside the current window (call under lock)."""
        cutoff = time.time() - self._window_seconds
        self._charges = [(ts, c) for ts, c in self._charges if ts >= cutoff]

    def _window_total(self) -> float:
        """Sum of charges inside the current window (call after _prune)."""
        return sum(c for _, c in self._charges)

    def current_spend(self) -> float:
        """Return total spend in the current window (thread-safe, read-only)."""
        with self._lock:
            self._prune()
            return self._window_total()

    def evaluate(self, text: str) -> PolicyResult:  # noqa: ARG002
        with self._lock:
            self._prune()
            current = self._window_total()
            projected = current + self.cost_per_request

            if projected > self.max_cost:
                return PolicyResult(
                    allowed=False,
                    reason=(
                        f"Cost cap exceeded: ${current:.4f} spent, "
                        f"cap is ${self.max_cost} per {self.per}"
                    ),
                    policy_name=self.name,
                    confidence=1.0,
                )

            # Charge for this request
            self._charges.append((time.time(), self.cost_per_request))
            return PolicyResult(
                allowed=True,
                reason=(
                    f"Cost OK: ${projected:.4f} of "
                    f"${self.max_cost} per {self.per}"
                ),
                policy_name=self.name,
                confidence=1.0,
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "cost_cap",
            "max_cost": self.max_cost,
            "per": self.per,
            "cost_per_request": self.cost_per_request,
            "name": self.name,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# CompositePolicy
# ---------------------------------------------------------------------------

class CompositePolicy(BasePolicy):
    """
    Boolean composition of two or more policies.

    * ``operator="and"`` — all child policies must pass
      (short-circuits on the first failure).
    * ``operator="or"``  — at least one child policy must pass
      (short-circuits on the first success).

    Nested compositions are supported, enabling arbitrarily complex trees.
    """

    def __init__(self, policies: List[BasePolicy], operator: str = "and",
                 name: str = "", version: str = POLICY_VERSION):
        if operator not in ("and", "or"):
            raise ValueError(
                f"operator must be 'and' or 'or', got {operator!r}"
            )
        self.policies = list(policies)
        self.operator = operator
        auto_name = name or f"composite_{operator}[{len(self.policies)}]"
        super().__init__(name=auto_name, version=version)

    def evaluate(self, text: str) -> PolicyResult:
        if not self.policies:
            return PolicyResult(
                allowed=True, reason="Empty composite policy",
                policy_name=self.name, confidence=1.0,
            )

        if self.operator == "and":
            for policy in self.policies:
                result = policy.evaluate(text)
                if not result.allowed:
                    # Short-circuit: return first failure
                    return PolicyResult(
                        allowed=False,
                        reason=f"[AND] blocked by {result.policy_name}: {result.reason}",
                        policy_name=self.name,
                        confidence=result.confidence,
                    )
            return PolicyResult(
                allowed=True,
                reason=f"[AND] all {len(self.policies)} policies passed",
                policy_name=self.name,
                confidence=1.0,
            )

        # operator == "or"
        last_result: Optional[PolicyResult] = None
        for policy in self.policies:
            result = policy.evaluate(text)
            if result.allowed:
                # Short-circuit: return first success
                return PolicyResult(
                    allowed=True,
                    reason=f"[OR] allowed by {result.policy_name}: {result.reason}",
                    policy_name=self.name,
                    confidence=result.confidence,
                )
            last_result = result

        last_reason = last_result.reason if last_result else "no policies"
        last_conf = last_result.confidence if last_result else 1.0
        return PolicyResult(
            allowed=False,
            reason=f"[OR] all {len(self.policies)} policies failed. Last: {last_reason}",
            policy_name=self.name,
            confidence=last_conf,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "composite",
            "operator": self.operator,
            "policies": [p.to_dict() for p in self.policies],
            "name": self.name,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# PolicyRegistry
# ---------------------------------------------------------------------------

class PolicyRegistry:
    """
    Named registry for policies.

    Usage::

        registry = PolicyRegistry()
        registry.register("strict", strict_policy)
        registry.get("strict")
        registry.list()  # ["strict"]
    """

    def __init__(self):
        self._registry: Dict[str, BasePolicy] = {}

    def register(self, name: str, policy: BasePolicy) -> None:
        """Register *policy* under *name*, replacing any existing entry."""
        if not isinstance(policy, BasePolicy):
            raise TypeError(
                f"policy must be a BasePolicy subclass, got {type(policy).__name__}"
            )
        self._registry[name] = policy

    def get(self, name: str) -> Optional[BasePolicy]:
        """Return the policy registered as *name*, or ``None``."""
        return self._registry.get(name)

    def list(self) -> List[str]:
        """Return a sorted list of all registered policy names."""
        return sorted(self._registry.keys())

    def unregister(self, name: str) -> bool:
        """Remove *name* from the registry.  Returns ``True`` if it existed."""
        if name in self._registry:
            del self._registry[name]
            return True
        return False

    def __len__(self) -> int:
        return len(self._registry)

    def __contains__(self, name: str) -> bool:
        return name in self._registry


# ---------------------------------------------------------------------------
# Convenience factory functions
# ---------------------------------------------------------------------------

def rate_limit_policy(requests: int, per: str = "minute",
                      **kwargs) -> RateLimitPolicy:
    """Create a :class:`RateLimitPolicy`."""
    return RateLimitPolicy(requests=requests, per=per, **kwargs)


def content_filter_policy(filter_type: str = "all",
                           **kwargs) -> ContentFilterPolicy:
    """Create a :class:`ContentFilterPolicy`."""
    return ContentFilterPolicy(filter_type=filter_type, **kwargs)


def cost_cap_policy(max_cost: float, per: str = "hour",
                    **kwargs) -> CostCapPolicy:
    """Create a :class:`CostCapPolicy`."""
    return CostCapPolicy(max_cost=max_cost, per=per, **kwargs)
