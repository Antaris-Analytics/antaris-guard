"""
ConversationGuard — stateful multi-turn attack detection.

Tracks security state across a conversation window (multiple turns) and
detects attacks that span multiple messages.

Zero dependencies, pure Python, deterministic.

Detected multi-turn patterns
-----------------------------
* ``gradual_escalation``      — safe early turns, escalating threat later
* ``repetition_attack``       — same injection attempt rephrased multiple times
* ``context_poisoning``       — repeated attempts to override system instructions
* ``distraction_then_attack`` — benign messages followed by sudden injection
* ``injection_attempt``       — single-turn direct injection
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, DefaultDict

from .guard import GuardResult, PromptGuard
from .patterns import ThreatLevel


# ---------------------------------------------------------------------------
# ConversationResult
# ---------------------------------------------------------------------------

@dataclass
class ConversationResult:
    """
    Result of :meth:`ConversationGuard.analyze_turn`.

    Attributes
    ----------
    allowed:
        ``True`` if this turn should be processed.
    guard_result:
        Underlying single-turn :class:`~antaris_guard.GuardResult`.
    conversation_risk_score:
        0–1 aggregate risk across the current conversation window.
    escalation_count:
        How many suspicious/blocked turns have been seen in the window.
    pattern_detected:
        Highest-priority multi-turn pattern name, or ``None``.
    multi_turn_pattern:
        Alias for :attr:`pattern_detected` (single-turn label).
    baseline_deviation:
        0–1 deviation from the source's established baseline.
        Always ``0.0`` when no baseline has been established.
    anomaly_detected:
        ``True`` when :attr:`baseline_deviation` > 0.5.
    blocked_by_escalation:
        ``True`` when the turn was allowed per-message but blocked because
        the conversation-level escalation threshold was reached.
    """

    allowed: bool
    guard_result: GuardResult
    conversation_risk_score: float
    escalation_count: int
    pattern_detected: Optional[str]
    multi_turn_pattern: Optional[str]
    baseline_deviation: float
    anomaly_detected: bool
    blocked_by_escalation: bool = False


# ---------------------------------------------------------------------------
# ConversationGuard
# ---------------------------------------------------------------------------

class ConversationGuard:
    """
    Stateful multi-turn attack detector.

    Usage::

        conv_guard = ConversationGuard(window_size=10, escalation_threshold=3)
        result = conv_guard.analyze_turn("some message", source_id="user_1")
        health = conv_guard.conversation_health()
        conv_guard.reset()

    Parameters
    ----------
    window_size:
        Number of recent turns to consider when computing risk metrics.
    escalation_threshold:
        Once this many suspicious/blocked turns accumulate inside the
        window, all subsequent turns are blocked regardless of their
        individual content.
    baseline_source_id:
        Optional source ID whose baseline is pre-populated on construction.
        Typically set to the primary user of a 1-to-1 chat session.
    guard:
        Optional :class:`~antaris_guard.PromptGuard` instance.  A default
        balanced-sensitivity guard is created when omitted.
    """

    # Similarity threshold — turns are "similar" when their content-hash
    # overlap exceeds this fraction.  Used for repetition-attack detection.
    _SIMILARITY_THRESHOLD: float = 0.6

    # Minimum turns required before baseline deviation is computed.
    _BASELINE_MIN_TURNS: int = 3

    # Deviation threshold — above this the turn is flagged as anomalous.
    _ANOMALY_THRESHOLD: float = 0.5

    # Keywords/phrases that signal context-poisoning attempts.
    _CONTEXT_POISON_SIGNALS = [
        "ignore previous",
        "forget previous",
        "disregard previous",
        "ignore all previous",
        "ignore your instructions",
        "override instructions",
        "new instructions",
        "your real instructions",
        "your system prompt",
        "reveal your prompt",
        "ignore the above",
        "disregard the above",
        "you are now",
        "act as if",
        "pretend you are",
        "from now on you",
    ]

    def __init__(
        self,
        window_size: int = 10,
        escalation_threshold: int = 3,
        baseline_source_id: Optional[str] = None,
        guard: Optional[PromptGuard] = None,
    ) -> None:
        self.window_size = max(1, window_size)
        self.escalation_threshold = max(1, escalation_threshold)
        self.baseline_source_id = baseline_source_id
        self._guard = guard or PromptGuard()

        # Turn history: list of dicts
        # {"text": str, "source_id": str, "timestamp": float,
        #  "threat_level": str, "score": float, "fingerprint": str}
        self._turns: List[Dict[str, Any]] = []

        # Per-source baselines: source_id → {"avg_score": float, "avg_len": float}
        self._baselines: Dict[str, Dict[str, float]] = {}

        # Per-source escalation counters (fix: prevent cross-source contamination)
        self._escalation_counts: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_turn(
        self,
        message: str,
        source_id: Optional[str] = None,
    ) -> ConversationResult:
        """
        Analyze a single conversation turn in context.

        Parameters
        ----------
        message:
            The user message for this turn.
        source_id:
            Identifier for the message source.  Defaults to
            ``"_default"`` when omitted.

        Returns
        -------
        ConversationResult
        """
        sid = source_id or "_default"
        now = time.time()

        # --- Single-turn analysis ---
        guard_result = self._guard.analyze(message)

        # --- Record turn ---
        record: Dict[str, Any] = {
            "text": message,
            "source_id": sid,
            "timestamp": now,
            "threat_level": guard_result.threat_level.value,
            "score": guard_result.score,
            "fingerprint": self._fingerprint(message),
        }
        self._turns.append(record)

        # Trim to window
        if len(self._turns) > self.window_size:
            self._turns = self._turns[-self.window_size :]

        window = self._turns  # already trimmed

        # --- Per-source escalation count (fix: filter by source_id to avoid
        #     contamination across sources sharing this guard instance) ---
        source_window = [t for t in window if t["source_id"] == sid]
        escalation_count = sum(
            1
            for t in source_window
            if t["threat_level"] in ("suspicious", "blocked")
        )
        self._escalation_counts[sid] = escalation_count
        conversation_risk_score = self._compute_risk_score(window)

        # --- Multi-turn pattern detection ---
        pattern = self._detect_pattern(window, message)

        # --- Baseline deviation ---
        baseline_deviation, anomaly_detected = self._compute_baseline_deviation(
            sid, message, guard_result.score
        )

        # --- Decide allowed ---
        blocked_by_escalation = False
        if guard_result.is_blocked:
            allowed = False
        elif escalation_count >= self.escalation_threshold:
            # Conversation-level block
            allowed = False
            blocked_by_escalation = True
        else:
            allowed = True

        return ConversationResult(
            allowed=allowed,
            guard_result=guard_result,
            conversation_risk_score=round(conversation_risk_score, 4),
            escalation_count=escalation_count,
            pattern_detected=pattern,
            multi_turn_pattern=pattern,
            baseline_deviation=round(baseline_deviation, 4),
            anomaly_detected=anomaly_detected,
            blocked_by_escalation=blocked_by_escalation,
        )

    def conversation_health(self) -> Dict[str, Any]:
        """
        Summarize the health of the current conversation window.

        Returns
        -------
        dict with keys:

        * ``risk_score``      — float 0–1
        * ``suspicious_turns`` — int
        * ``total_turns``     — int
        * ``status``          — ``"healthy"``, ``"elevated"``, or ``"critical"``
        """
        window = self._turns
        total = len(window)
        suspicious = sum(
            1 for t in window if t["threat_level"] in ("suspicious", "blocked")
        )
        risk = self._compute_risk_score(window)

        if risk < 0.2:
            status = "healthy"
        elif risk < 0.6:
            status = "elevated"
        else:
            status = "critical"

        return {
            "risk_score": round(risk, 4),
            "suspicious_turns": suspicious,
            "total_turns": total,
            "status": status,
        }

    def establish_baseline(self, source_id: str) -> None:
        """
        Compute a behavioral baseline for *source_id* from existing turns.

        Call this after the source has made enough benign turns so that
        future deviations can be measured.  Requires at least
        :attr:`_BASELINE_MIN_TURNS` turns from the source.

        Parameters
        ----------
        source_id:
            The source whose turns to baseline.
        """
        source_turns = [t for t in self._turns if t["source_id"] == source_id]
        if len(source_turns) < self._BASELINE_MIN_TURNS:
            return  # Not enough data yet

        avg_score = sum(t["score"] for t in source_turns) / len(source_turns)
        avg_len = sum(len(t["text"]) for t in source_turns) / len(source_turns)
        self._baselines[source_id] = {
            "avg_score": avg_score,
            "avg_len": avg_len,
            "sample_size": len(source_turns),
        }

    def reset(self) -> None:
        """Clear all conversation state (turns, baselines, escalation counts)."""
        self._turns.clear()
        self._baselines.clear()
        self._escalation_counts.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(text: str) -> str:
        """Lightweight content fingerprint for similarity comparison."""
        # Normalize: lowercase, strip punctuation, sort words
        words = sorted(
            w.strip(".,!?;:\"'()[]{}") for w in text.lower().split()
            if len(w) > 2
        )
        raw = " ".join(words)
        return hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()[:8]

    @staticmethod
    def _jaccard(a: str, b: str) -> float:
        """Jaccard similarity between two texts (word level)."""
        sa = set(a.lower().split())
        sb = set(b.lower().split())
        if not sa and not sb:
            return 1.0
        if not sa or not sb:
            return 0.0
        return len(sa & sb) / len(sa | sb)

    def _compute_risk_score(self, window: List[Dict[str, Any]]) -> float:
        """Aggregate risk score across the window (0–1)."""
        if not window:
            return 0.0
        weights = {"safe": 0.0, "suspicious": 0.4, "blocked": 1.0}
        total = sum(weights.get(t["threat_level"], 0.0) for t in window)
        return min(1.0, total / len(window))

    def _detect_pattern(
        self,
        window: List[Dict[str, Any]],
        current_message: str,
    ) -> Optional[str]:
        """
        Identify multi-turn attack patterns.

        Returns the highest-priority pattern name, or ``None``.
        Priority order (highest first):

        1. ``context_poisoning``
        2. ``repetition_attack``
        3. ``gradual_escalation``
        4. ``distraction_then_attack``
        5. ``injection_attempt``
        """
        text_lower = current_message.lower()

        # 1. Context poisoning — explicit instruction-override language
        for signal in self._CONTEXT_POISON_SIGNALS:
            if signal in text_lower:
                return "context_poisoning"

        # 2. Injection attempt (single-turn) from guard result classification
        #    — checked here so it can be superseded by multi-turn patterns
        is_injection = (
            len(window) > 0
            and window[-1]["threat_level"] in ("suspicious", "blocked")
        )

        # 3. Repetition attack — same injection rephrased ≥ 2 times
        if len(window) >= 2:
            threat_turns = [
                t for t in window if t["threat_level"] in ("suspicious", "blocked")
            ]
            if len(threat_turns) >= 2:
                # Check pairwise similarity among threat turns
                for i in range(len(threat_turns)):
                    for j in range(i + 1, len(threat_turns)):
                        sim = self._jaccard(
                            threat_turns[i]["text"], threat_turns[j]["text"]
                        )
                        if sim >= self._SIMILARITY_THRESHOLD:
                            return "repetition_attack"

        # 4. Gradual escalation — early turns safe, later turns threatening
        if len(window) >= 4:
            mid = len(window) // 2
            first_half = window[:mid]
            second_half = window[mid:]

            def _threat_rate(turns):
                return sum(
                    1 for t in turns if t["threat_level"] in ("suspicious", "blocked")
                ) / len(turns)

            first_rate = _threat_rate(first_half)
            second_rate = _threat_rate(second_half)

            if second_rate > first_rate + 0.3 and second_rate >= 0.25:
                return "gradual_escalation"

        # 5. Distraction then attack — many benign then sudden threat
        if len(window) >= 4:
            lead = window[:-1]
            benign_lead = all(t["threat_level"] == "safe" for t in lead)
            current_threat = window[-1]["threat_level"] in ("suspicious", "blocked")
            if benign_lead and current_threat and len(lead) >= 3:
                return "distraction_then_attack"

        # 6. Generic single injection label
        if is_injection:
            return "injection_attempt"

        return None

    def _compute_baseline_deviation(
        self,
        source_id: str,
        message: str,
        score: float,
    ) -> tuple:  # (float, bool)
        """
        Return (deviation, anomaly_detected) for the given turn.

        If no baseline exists for *source_id* the deviation is 0.0.
        """
        baseline = self._baselines.get(source_id)
        if baseline is None:
            return 0.0, False

        avg_score = baseline["avg_score"]
        avg_len = baseline["avg_len"]

        # Score deviation: how much higher is this turn's risk?
        score_dev = abs(score - avg_score)

        # Length deviation (normalized): >3× baseline length is suspicious
        if avg_len > 0:
            len_dev = min(1.0, abs(len(message) - avg_len) / max(avg_len, 1))
        else:
            len_dev = 0.0

        # Combined deviation (score-weighted 70%, length 30%)
        deviation = min(1.0, score_dev * 0.7 + len_dev * 0.3)
        anomaly = deviation > self._ANOMALY_THRESHOLD
        return deviation, anomaly
