"""
Stateful conversation-level policies for antaris-guard (Sprint 2.5).

Extends the stateless policy DSL in policy.py with conversation-aware
policies that track state ACROSS a conversation window.

Zero dependencies, pure Python, thread-safe.

Detected patterns
-----------------
* Escalation detection  — N increasingly hostile messages in a window
* Repeated boundary testing — suspicious messages after prior threats
* Burst detection       — too many requests in a short time window

Usage::

    from antaris_guard.policies import (
        EscalationPolicy,
        BurstPolicy,
        BoundaryTestPolicy,
    )
    from antaris_guard.conversation_state import ConversationStateStore

    store = ConversationStateStore()
    policy = EscalationPolicy(threshold=3, window=10, store=store)

    result = policy.evaluate_with_context(text, conversation_id="conv_123",
                                          threat_level="suspicious", score=0.8)
"""
import time
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from .conversation_state import ConversationState, ConversationStateStore


# ---------------------------------------------------------------------------
# StatefulPolicyResult
# ---------------------------------------------------------------------------

class StatefulPolicyResult:
    """
    Result from a stateful policy evaluation.

    Attributes
    ----------
    allowed:
        True when the request should be permitted.
    reason:
        Human-readable explanation.
    policy_name:
        Name of the policy that produced this result.
    confidence:
        0.0–1.0 certainty of the decision.
    evidence:
        Dict of supporting evidence (counts, timestamps, etc.) for audit.
    """

    __slots__ = ("allowed", "reason", "policy_name", "confidence", "evidence")

    def __init__(
        self,
        allowed: bool,
        reason: str,
        policy_name: str,
        confidence: float = 1.0,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.allowed = allowed
        self.reason = reason
        self.policy_name = policy_name
        self.confidence = max(0.0, min(1.0, confidence))
        self.evidence = evidence or {}

    def __repr__(self) -> str:  # pragma: no cover
        verdict = "ALLOW" if self.allowed else "DENY"
        return (
            f"StatefulPolicyResult({verdict}, policy={self.policy_name!r}, "
            f"reason={self.reason!r})"
        )


# ---------------------------------------------------------------------------
# StatefulPolicy base
# ---------------------------------------------------------------------------

class StatefulPolicy(ABC):
    """
    Abstract base for conversation-level stateful policies.

    Unlike :class:`~antaris_guard.policy.BasePolicy`, stateful policies
    receive the *conversation_id* and current message metadata so they can
    inspect and update accumulated conversation state.

    Subclasses implement :meth:`evaluate_with_context`.
    """

    def __init__(self, name: str = "", store: Optional[ConversationStateStore] = None) -> None:
        self.name = name or self.__class__.__name__
        self._store = store or ConversationStateStore()

    # ------------------------------------------------------------------
    # Core interface
    # ------------------------------------------------------------------

    @abstractmethod
    def evaluate_with_context(
        self,
        text: str,
        conversation_id: str,
        threat_level: str = "safe",
        score: float = 0.0,
        cost: float = 0.0,
    ) -> StatefulPolicyResult:
        """
        Evaluate *text* in the context of *conversation_id*.

        Parameters
        ----------
        text:
            Current message text.
        conversation_id:
            Conversation this message belongs to.
        threat_level:
            Result from upstream pattern analysis: ``"safe"``,
            ``"suspicious"``, or ``"blocked"``.
        score:
            Float threat score 0.0–1.0 from upstream analysis.
        cost:
            Estimated cost in USD for this request.
        """
        ...

    # ------------------------------------------------------------------
    # Boolean composition
    # ------------------------------------------------------------------

    def __and__(self, other: "StatefulPolicy") -> "CompositeStatefulPolicy":
        return CompositeStatefulPolicy([self, other], operator="and")

    def __or__(self, other: "StatefulPolicy") -> "CompositeStatefulPolicy":
        return CompositeStatefulPolicy([self, other], operator="or")


# ---------------------------------------------------------------------------
# EscalationPolicy
# ---------------------------------------------------------------------------

class EscalationPolicy(StatefulPolicy):
    """
    Block when a conversation accumulates *threshold* or more
    suspicious/blocked messages within a sliding *window* of recent turns.

    This detects gradual boundary-testing where each individual message
    might be only mildly suspicious but the pattern across turns reveals
    intent.

    Parameters
    ----------
    threshold:
        Number of suspicious/blocked turns that triggers a block
        (default: 3).
    window:
        How many recent messages to consider (default: 10).
    store:
        Shared :class:`~antaris_guard.conversation_state.ConversationStateStore`.
    name:
        Human-readable policy name.
    """

    def __init__(
        self,
        threshold: int = 3,
        window: int = 10,
        store: Optional[ConversationStateStore] = None,
        name: str = "",
    ) -> None:
        self.threshold = max(1, threshold)
        self.window = max(1, window)
        super().__init__(name=name or f"escalation_threshold_{threshold}", store=store)

    def evaluate_with_context(
        self,
        text: str,
        conversation_id: str,
        threat_level: str = "safe",
        score: float = 0.0,
        cost: float = 0.0,
    ) -> StatefulPolicyResult:
        state = self._store.record_message(
            conversation_id, text, threat_level, score, cost
        )

        # Count threat turns in the recent window
        recent = state.messages[-self.window:]
        escalation_count = sum(
            1 for m in recent if m.threat_level in ("suspicious", "blocked")
        )

        if escalation_count >= self.threshold:
            return StatefulPolicyResult(
                allowed=False,
                reason=(
                    f"Escalation threshold reached: {escalation_count} "
                    f"hostile messages in last {len(recent)} turns "
                    f"(threshold={self.threshold})"
                ),
                policy_name=self.name,
                confidence=0.95,
                evidence={
                    "escalation_count": escalation_count,
                    "window_size": len(recent),
                    "threshold": self.threshold,
                    "conversation_id": conversation_id,
                },
            )

        return StatefulPolicyResult(
            allowed=True,
            reason=(
                f"Escalation OK: {escalation_count}/{self.threshold} "
                f"hostile messages in last {len(recent)} turns"
            ),
            policy_name=self.name,
            confidence=1.0,
            evidence={
                "escalation_count": escalation_count,
                "window_size": len(recent),
                "threshold": self.threshold,
            },
        )


# ---------------------------------------------------------------------------
# BurstPolicy
# ---------------------------------------------------------------------------

class BurstPolicy(StatefulPolicy):
    """
    Block when a conversation exceeds *max_requests* messages within
    *window_seconds*.

    Detects bot-like rapid-fire request patterns within a single
    conversation session.

    Parameters
    ----------
    max_requests:
        Maximum allowed messages in the time window (default: 20).
    window_seconds:
        Width of the sliding time window in seconds (default: 60).
    store:
        Shared :class:`~antaris_guard.conversation_state.ConversationStateStore`.
    name:
        Human-readable policy name.
    """

    def __init__(
        self,
        max_requests: int = 20,
        window_seconds: float = 60.0,
        store: Optional[ConversationStateStore] = None,
        name: str = "",
    ) -> None:
        self.max_requests = max(1, max_requests)
        self.window_seconds = max(0.001, window_seconds)
        super().__init__(
            name=name or f"burst_{max_requests}_per_{int(window_seconds)}s",
            store=store,
        )

    def evaluate_with_context(
        self,
        text: str,
        conversation_id: str,
        threat_level: str = "safe",
        score: float = 0.0,
        cost: float = 0.0,
    ) -> StatefulPolicyResult:
        # Record the message first, then count the burst window
        state = self._store.record_message(
            conversation_id, text, threat_level, score, cost
        )

        cutoff = time.time() - self.window_seconds
        burst_count = sum(
            1 for m in state.messages if m.timestamp >= cutoff
        )

        if burst_count > self.max_requests:
            return StatefulPolicyResult(
                allowed=False,
                reason=(
                    f"Burst limit exceeded: {burst_count} messages in "
                    f"last {self.window_seconds:.0f}s "
                    f"(max={self.max_requests})"
                ),
                policy_name=self.name,
                confidence=1.0,
                evidence={
                    "burst_count": burst_count,
                    "window_seconds": self.window_seconds,
                    "max_requests": self.max_requests,
                    "conversation_id": conversation_id,
                },
            )

        return StatefulPolicyResult(
            allowed=True,
            reason=(
                f"Burst OK: {burst_count}/{self.max_requests} "
                f"in last {self.window_seconds:.0f}s"
            ),
            policy_name=self.name,
            confidence=1.0,
            evidence={
                "burst_count": burst_count,
                "window_seconds": self.window_seconds,
            },
        )


# ---------------------------------------------------------------------------
# BoundaryTestPolicy
# ---------------------------------------------------------------------------

class BoundaryTestPolicy(StatefulPolicy):
    """
    Detect and block repeated boundary-testing behaviour.

    A boundary test is identified when a conversation has more than
    *max_boundary_tests* messages flagged as ``is_boundary_test=True``
    (i.e., suspicious/blocked messages that follow prior threats) within
    the recent *window* turns.

    Parameters
    ----------
    max_boundary_tests:
        How many boundary-test messages are tolerated before blocking
        (default: 2).
    window:
        How many recent messages to inspect (default: 20).
    store:
        Shared :class:`~antaris_guard.conversation_state.ConversationStateStore`.
    name:
        Human-readable policy name.
    """

    def __init__(
        self,
        max_boundary_tests: int = 2,
        window: int = 20,
        store: Optional[ConversationStateStore] = None,
        name: str = "",
    ) -> None:
        self.max_boundary_tests = max(1, max_boundary_tests)
        self.window = max(1, window)
        super().__init__(
            name=name or f"boundary_test_max_{max_boundary_tests}",
            store=store,
        )

    def evaluate_with_context(
        self,
        text: str,
        conversation_id: str,
        threat_level: str = "safe",
        score: float = 0.0,
        cost: float = 0.0,
    ) -> StatefulPolicyResult:
        state = self._store.record_message(
            conversation_id, text, threat_level, score, cost
        )

        recent = state.messages[-self.window:]
        boundary_count = sum(1 for m in recent if m.is_boundary_test)

        if boundary_count > self.max_boundary_tests:
            return StatefulPolicyResult(
                allowed=False,
                reason=(
                    f"Repeated boundary testing detected: {boundary_count} "
                    f"boundary-probe messages in last {len(recent)} turns "
                    f"(max={self.max_boundary_tests})"
                ),
                policy_name=self.name,
                confidence=0.90,
                evidence={
                    "boundary_test_count": boundary_count,
                    "window_size": len(recent),
                    "max_boundary_tests": self.max_boundary_tests,
                    "conversation_id": conversation_id,
                },
            )

        return StatefulPolicyResult(
            allowed=True,
            reason=(
                f"Boundary test OK: {boundary_count}/{self.max_boundary_tests}"
            ),
            policy_name=self.name,
            confidence=1.0,
            evidence={
                "boundary_test_count": boundary_count,
                "window_size": len(recent),
            },
        )


# ---------------------------------------------------------------------------
# ConversationCostCapPolicy
# ---------------------------------------------------------------------------

class ConversationCostCapPolicy(StatefulPolicy):
    """
    Block when cumulative cost for a single conversation exceeds *max_usd*.

    Unlike :class:`~antaris_guard.policy.CostCapPolicy` which tracks cost
    in a global sliding window, this policy is scoped to a single
    *conversation_id*.

    Parameters
    ----------
    max_usd:
        Maximum allowed cumulative cost per conversation in USD.
    cost_per_request:
        Default cost charged per request if not passed in *cost*.
    store:
        Shared :class:`~antaris_guard.conversation_state.ConversationStateStore`.
    name:
        Human-readable policy name.
    """

    def __init__(
        self,
        max_usd: float,
        cost_per_request: float = 0.001,
        store: Optional[ConversationStateStore] = None,
        name: str = "",
    ) -> None:
        self.max_usd = max(0.0, max_usd)
        self.cost_per_request = max(0.0, cost_per_request)
        super().__init__(name=name or f"conv_cost_cap_{max_usd:.3f}", store=store)

    def evaluate_with_context(
        self,
        text: str,
        conversation_id: str,
        threat_level: str = "safe",
        score: float = 0.0,
        cost: float = 0.0,
    ) -> StatefulPolicyResult:
        # Use supplied cost or default
        effective_cost = cost if cost > 0.0 else self.cost_per_request

        # Check BEFORE recording to avoid charging for denied requests
        existing_state = self._store.get(conversation_id)
        current_spend = existing_state.total_cost if existing_state else 0.0
        projected = current_spend + effective_cost

        if projected > self.max_usd:
            # Still record the message (at zero cost) so other policies see it
            self._store.record_message(
                conversation_id, text, threat_level, score, cost=0.0
            )
            return StatefulPolicyResult(
                allowed=False,
                reason=(
                    f"Conversation cost cap exceeded: "
                    f"${current_spend:.4f} spent, "
                    f"cap is ${self.max_usd:.4f} per conversation"
                ),
                policy_name=self.name,
                confidence=1.0,
                evidence={
                    "current_spend": current_spend,
                    "projected_spend": projected,
                    "max_usd": self.max_usd,
                    "conversation_id": conversation_id,
                },
            )

        self._store.record_message(
            conversation_id, text, threat_level, score, cost=effective_cost
        )
        return StatefulPolicyResult(
            allowed=True,
            reason=(
                f"Conversation cost OK: "
                f"${projected:.4f} of ${self.max_usd:.4f}"
            ),
            policy_name=self.name,
            confidence=1.0,
            evidence={
                "current_spend": current_spend,
                "projected_spend": projected,
                "max_usd": self.max_usd,
            },
        )


# ---------------------------------------------------------------------------
# CompositeStatefulPolicy
# ---------------------------------------------------------------------------

class CompositeStatefulPolicy(StatefulPolicy):
    """
    Boolean composition of stateful policies.

    * ``operator="and"`` — all child policies must pass (short-circuits on
      first failure).
    * ``operator="or"``  — any child policy passing is sufficient
      (short-circuits on first success).

    Parameters
    ----------
    policies:
        List of child :class:`StatefulPolicy` instances.
    operator:
        ``"and"`` or ``"or"``.
    name:
        Human-readable policy name (auto-generated if omitted).
    store:
        Ignored; each child policy owns its own store reference.
    """

    def __init__(
        self,
        policies: List[StatefulPolicy],
        operator: str = "and",
        name: str = "",
        store: Optional[ConversationStateStore] = None,
    ) -> None:
        if operator not in ("and", "or"):
            raise ValueError(
                f"operator must be 'and' or 'or', got {operator!r}"
            )
        self.policies = list(policies)
        self.operator = operator
        auto_name = name or f"composite_{operator}[{len(self.policies)}]"
        # Pass store=None; CompositeStatefulPolicy doesn't own a store itself
        super().__init__(name=auto_name, store=ConversationStateStore())

    def evaluate_with_context(
        self,
        text: str,
        conversation_id: str,
        threat_level: str = "safe",
        score: float = 0.0,
        cost: float = 0.0,
    ) -> StatefulPolicyResult:
        if not self.policies:
            return StatefulPolicyResult(
                allowed=True,
                reason="Empty composite policy",
                policy_name=self.name,
                confidence=1.0,
            )

        if self.operator == "and":
            for policy in self.policies:
                result = policy.evaluate_with_context(
                    text, conversation_id, threat_level, score, cost
                )
                if not result.allowed:
                    return StatefulPolicyResult(
                        allowed=False,
                        reason=f"[AND] blocked by {result.policy_name}: {result.reason}",
                        policy_name=self.name,
                        confidence=result.confidence,
                        evidence=result.evidence,
                    )
            return StatefulPolicyResult(
                allowed=True,
                reason=f"[AND] all {len(self.policies)} policies passed",
                policy_name=self.name,
                confidence=1.0,
            )

        # operator == "or"
        last_result: Optional[StatefulPolicyResult] = None
        for policy in self.policies:
            result = policy.evaluate_with_context(
                text, conversation_id, threat_level, score, cost
            )
            if result.allowed:
                return StatefulPolicyResult(
                    allowed=True,
                    reason=f"[OR] allowed by {result.policy_name}: {result.reason}",
                    policy_name=self.name,
                    confidence=result.confidence,
                    evidence=result.evidence,
                )
            last_result = result

        last_reason = last_result.reason if last_result else "no policies"
        last_conf = last_result.confidence if last_result else 1.0
        last_ev = last_result.evidence if last_result else {}
        return StatefulPolicyResult(
            allowed=False,
            reason=f"[OR] all {len(self.policies)} policies failed. Last: {last_reason}",
            policy_name=self.name,
            confidence=last_conf,
            evidence=last_ev,
        )
