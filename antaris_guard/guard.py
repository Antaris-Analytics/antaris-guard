"""
PromptGuard - Main security class for analyzing input text and detecting injection attempts.
"""
import json
import logging
import os
import re
import threading
import time
from typing import Dict, List, Optional, Set, Any, TYPE_CHECKING
from dataclasses import dataclass
from .patterns import PatternMatcher, ThreatLevel, PATTERN_VERSION
from .normalizer import normalize
from .utils import atomic_write_json

if TYPE_CHECKING:
    from .behavior import BehaviorAnalyzer
    from .reputation import ReputationTracker
    from .policies import StatefulPolicy
    from .conversation_state import ConversationStateStore
    from .audit import AuditLogger

logger = logging.getLogger(__name__)


@dataclass
class GuardResult:
    """Result of a security analysis."""
    threat_level: ThreatLevel
    is_safe: bool
    is_suspicious: bool
    is_blocked: bool
    matches: List[Dict[str, Any]]
    score: float  # 0.0 (safe) to 1.0 (definitely malicious)
    message: str
    pattern_version: str = PATTERN_VERSION


class SensitivityLevel:
    """Sensitivity level configuration."""
    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"


class PromptGuard:
    """
    Main security guard for analyzing input text and detecting injection attempts.
    
    Features:
    - Pattern-based detection using regex rules
    - Configurable sensitivity levels
    - Allowlist/blocklist support  
    - Threat scoring and classification
    """
    
    def __init__(self, config_path: Optional[str] = None,
                 sensitivity: str = SensitivityLevel.BALANCED,
                 pattern_matcher: Optional[PatternMatcher] = None,
                 policy=None,
                 policy_file: Optional[str] = None,
                 watch_policy_file: bool = False,
                 behavior_analyzer: Optional["BehaviorAnalyzer"] = None,
                 reputation_tracker: Optional["ReputationTracker"] = None,
                 stateful_policy: Optional["StatefulPolicy"] = None,
                 audit_logger: Optional["AuditLogger"] = None):
        """
        Initialize PromptGuard.

        Args:
            config_path:         Path to JSON configuration file.
            sensitivity:         Sensitivity level (strict/balanced/permissive).
            pattern_matcher:     Custom PatternMatcher instance. Use this to
                                 supply your own pattern sets and version.
                                 Defaults to built-in patterns.
            policy:              Optional :class:`~antaris_guard.policy.BasePolicy`
                                 (or composite) applied *before* pattern analysis.
                                 When the policy denies a request, ``analyze()``
                                 returns a BLOCKED result immediately.
            policy_file:         Path to a JSON policy file.  When supplied,
                                 the policy is loaded from the file and overrides
                                 the ``policy`` kwarg.  The file must contain a
                                 ``BasePolicy.to_dict()``-compatible structure plus
                                 an optional ``"version"`` key at the top level.
            watch_policy_file:   When ``True`` and ``policy_file`` is set, a
                                 background thread watches the file for mtime
                                 changes and calls :meth:`reload_policy`
                                 automatically.
            behavior_analyzer:   Optional :class:`~antaris_guard.behavior.BehaviorAnalyzer`
                                 instance.  When provided, ``analyze()`` automatically
                                 calls ``behavior_analyzer.record(source_id, ...)``
                                 after each analysis so behavioral patterns are tracked.
            reputation_tracker:  Optional :class:`~antaris_guard.reputation.ReputationTracker`
                                 instance.  When provided, ``analyze()`` automatically
                                 calls ``reputation_tracker.record_interaction(source_id, ...)``
                                 after each analysis.

        Example::

            from antaris_guard import PromptGuard, BehaviorAnalyzer, ReputationTracker

            ba = BehaviorAnalyzer(store_path="./behavior.json")
            rt = ReputationTracker(store_path="./reputation.json")
            guard = PromptGuard(behavior_analyzer=ba, reputation_tracker=rt)

            result = guard.analyze("some input", source_id="user_42")
            # BehaviorAnalyzer and ReputationTracker are updated automatically.
        """
        self.sensitivity = sensitivity
        self.pattern_matcher = pattern_matcher or PatternMatcher()
        self.allowlist: Set[str] = set()
        self.blocklist: Set[str] = set()
        # When True, allowlist/blocklist use whole-word matching instead of substring
        self.allowlist_exact: bool = False
        self.blocklist_exact: bool = False
        self.custom_patterns: List[tuple] = []

        # Optional policy (Sprint 4)
        self.policy = policy

        # Optional behavioral integration hooks
        self.behavior_analyzer = behavior_analyzer
        self.reputation_tracker = reputation_tracker

        # Optional stateful conversation-level policy (Sprint 2.5)
        self.stateful_policy: Optional["StatefulPolicy"] = stateful_policy

        # Optional audit logger for policy decisions (Sprint 2.5)
        self.audit_logger: Optional["AuditLogger"] = audit_logger

        # --- Policy file support (Sprint 10) ---
        self._policy_file: Optional[str] = policy_file
        self._policy_version: str = "0"
        self._policy_file_mtime: float = 0.0
        self._policy_watch_thread: Optional[threading.Thread] = None
        self._policy_watch_stop: threading.Event = threading.Event()

        if policy_file:
            self.reload_policy()  # loads and sets self.policy + self._policy_version

        if watch_policy_file and policy_file:
            self._start_policy_watcher()

        # Integration hooks — callables invoked on specific events
        # Signature: callback(result: GuardResult, text: str) -> None
        self._hooks: Dict[str, List] = {
            'on_blocked': [],
            'on_suspicious': [],
            'on_safe': [],
            'on_any': [],
        }

        # In-memory stats for get_pattern_stats() — list of stat records
        # Each record: {"timestamp": float, "blocked": bool, "patterns": [str], "risk": str}
        self._analysis_stats: List[Dict[str, Any]] = []
        self._stats_max: int = 10_000  # cap to avoid unbounded growth

        # Load configuration if provided
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
    
    def _load_config(self, config_path: str) -> None:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            self.sensitivity = config.get('sensitivity', self.sensitivity)
            self.allowlist.update(config.get('allowlist', []))
            self.blocklist.update(config.get('blocklist', []))
            
            # Load custom patterns
            custom_patterns = config.get('custom_patterns', [])
            for pattern_data in custom_patterns:
                pattern = pattern_data.get('pattern')
                threat_level_str = pattern_data.get('threat_level', 'suspicious')
                if pattern:
                    threat_level = ThreatLevel(threat_level_str)
                    self.custom_patterns.append((pattern, threat_level))
                    
        except FileNotFoundError:
            pass  # No config file = use defaults
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning("Corrupt guard config at %s: %s — using defaults", config_path, e)
    
    def save_config(self, config_path: str) -> None:
        """Save current configuration to JSON file."""
        config = {
            'sensitivity': self.sensitivity,
            'allowlist': list(self.allowlist),
            'blocklist': list(self.blocklist),
            'custom_patterns': [
                {
                    'pattern': pattern,
                    'threat_level': threat_level.value
                }
                for pattern, threat_level in self.custom_patterns
            ]
        }
        atomic_write_json(config_path, config)
    
    def add_to_allowlist(self, text: str) -> None:
        """Add text to allowlist (will be considered safe)."""
        self.allowlist.add(text.lower().strip())
    
    def add_to_blocklist(self, text: str) -> None:
        """Add text to blocklist (will be blocked)."""
        self.blocklist.add(text.lower().strip())
    
    def remove_from_allowlist(self, text: str) -> None:
        """Remove text from allowlist."""
        self.allowlist.discard(text.lower().strip())
    
    def remove_from_blocklist(self, text: str) -> None:
        """Remove text from blocklist."""
        self.blocklist.discard(text.lower().strip())
    
    def add_custom_pattern(self, pattern: str, threat_level: ThreatLevel) -> None:
        """Add a custom detection pattern."""
        self.custom_patterns.append((pattern, threat_level))
    
    def add_hook(self, event: str, callback) -> None:
        """
        Register an integration hook.
        
        Args:
            event: Event type — 'on_blocked', 'on_suspicious', 'on_safe', or 'on_any'
            callback: Callable with signature (result: GuardResult, text: str) -> None.
                      Exceptions in callbacks are caught and logged, never propagated.
        
        Raises:
            ValueError: If event type is not recognized
        """
        if event not in self._hooks:
            raise ValueError(f"Unknown hook event '{event}'. Valid: {list(self._hooks.keys())}")
        self._hooks[event].append(callback)
    
    def remove_hook(self, event: str, callback) -> bool:
        """Remove a previously registered hook. Returns True if found."""
        if event in self._hooks:
            try:
                self._hooks[event].remove(callback)
                return True
            except ValueError:
                return False
        return False
    
    def _dispatch_hooks(self, result: 'GuardResult', text: str) -> None:
        """Fire registered hooks for the given result."""
        # Always-fire hooks
        for cb in self._hooks['on_any']:
            try:
                cb(result, text)
            except Exception as e:
                logger.warning("Hook on_any raised: %s", e)
        
        # Event-specific hooks
        if result.is_blocked:
            event_key = 'on_blocked'
        elif result.is_suspicious:
            event_key = 'on_suspicious'
        else:
            event_key = 'on_safe'
        
        for cb in self._hooks[event_key]:
            try:
                cb(result, text)
            except Exception as e:
                logger.warning("Hook %s raised: %s", event_key, e)
    
    def _check_allowlist(self, text: str) -> bool:
        """
        Check if text matches allowlist.
        
        WARNING: When allowlist_exact=False (default), this is substring-based.
        Allowlisting a short string like "ignore" would disable injection
        detection for any input containing that word. Use allowlist_exact=True
        or allowlist full phrases to avoid this footgun.
        """
        text_lower = text.lower().strip()
        if self.allowlist_exact:
            return text_lower in self.allowlist
        return any(allowed in text_lower for allowed in self.allowlist)
    
    def _check_blocklist(self, text: str) -> bool:
        """Check if text matches blocklist.""" 
        text_lower = text.lower().strip()
        if self.blocklist_exact:
            return text_lower in self.blocklist
        return any(blocked in text_lower for blocked in self.blocklist)
    
    def _calculate_score(self, matches: List[tuple], text_length: int) -> float:
        """
        Calculate threat score based on matches and sensitivity.
        
        Returns score from 0.0 (safe) to 1.0 (definitely malicious).
        Score is based on match severity, not text length.
        """
        if not matches:
            return 0.0
        
        # Score by severity — each match contributes independently
        blocked_count = sum(1 for _, threat_level, _ in matches if threat_level == ThreatLevel.BLOCKED)
        suspicious_count = sum(1 for _, threat_level, _ in matches if threat_level == ThreatLevel.SUSPICIOUS)
        
        # Blocked matches contribute 0.4 each (capped), suspicious 0.15 each
        base_score = min(1.0, blocked_count * 0.4 + suspicious_count * 0.15)
        
        # Apply sensitivity multiplier
        sensitivity_multiplier = {
            SensitivityLevel.STRICT: 1.3,
            SensitivityLevel.BALANCED: 1.0, 
            SensitivityLevel.PERMISSIVE: 0.7
        }.get(self.sensitivity, 1.0)
        
        score = base_score * sensitivity_multiplier
        return min(1.0, score)
    
    def _get_sensitivity_thresholds(self) -> tuple:
        """Get threat thresholds based on sensitivity level."""
        if self.sensitivity == SensitivityLevel.STRICT:
            return 0.2, 0.4  # suspicious_threshold, blocked_threshold
        elif self.sensitivity == SensitivityLevel.PERMISSIVE:
            return 0.6, 0.8
        else:  # balanced
            return 0.4, 0.6
    
    def analyze(self, text: str, source_id: Optional[str] = None) -> GuardResult:
        """
        Analyze text for potential security threats.

        When a :attr:`policy` is attached, it is evaluated first.  A policy
        denial produces an immediate BLOCKED result (policy short-circuits
        the full pattern scan).

        If :attr:`behavior_analyzer` or :attr:`reputation_tracker` were
        supplied at construction, they are automatically updated after each
        analysis using the resolved *source_id* (defaults to ``"_default"``
        when omitted).

        Args:
            text:      Input text to analyze.
            source_id: Optional identifier for the request source (user, session
                       ID, IP address, etc.).  Used to route results to the
                       optional :attr:`behavior_analyzer` and
                       :attr:`reputation_tracker`.

        Returns:
            GuardResult with threat assessment
        """
        pv = self.pattern_matcher.pattern_version

        if not text or not text.strip():
            return GuardResult(
                threat_level=ThreatLevel.SAFE,
                is_safe=True,
                is_suspicious=False,
                is_blocked=False,
                matches=[],
                score=0.0,
                message="Empty input",
                pattern_version=pv,
            )

        # ------------------------------------------------------------------
        # Policy gate (Sprint 4) — evaluated before pattern matching.
        # ------------------------------------------------------------------
        if self.policy is not None:
            policy_result = self.policy.evaluate(text)
            if not policy_result.allowed:
                result = GuardResult(
                    threat_level=ThreatLevel.BLOCKED,
                    is_safe=False,
                    is_suspicious=False,
                    is_blocked=True,
                    matches=[{
                        'type': 'policy',
                        'policy_name': policy_result.policy_name,
                        'text': policy_result.reason,
                        'position': 0,
                        'threat_level': ThreatLevel.BLOCKED.value,
                        'confidence': policy_result.confidence,
                    }],
                    score=1.0,
                    message=f"Policy denied: {policy_result.reason}",
                    pattern_version=pv,
                )
                self._record_stat(result, text)
                self._dispatch_hooks(result, text)
                self._notify_integrations(result, source_id)
                return result
        
        text = text.strip()
        
        # Normalize for evasion resistance
        normalized_text, _ = normalize(text)
        
        # Check allowlist first
        if self._check_allowlist(text):
            result = GuardResult(
                threat_level=ThreatLevel.SAFE,
                is_safe=True,
                is_suspicious=False,
                is_blocked=False,
                matches=[],
                score=0.0,
                message="Allowlisted content",
                pattern_version=pv,
            )
            self._dispatch_hooks(result, text)
            self._notify_integrations(result, source_id)
            return result
        
        # Check blocklist
        if self._check_blocklist(text):
            result = GuardResult(
                threat_level=ThreatLevel.BLOCKED,
                is_safe=False,
                is_suspicious=False,
                is_blocked=True,
                matches=[{
                    'type': 'blocklist',
                    'text': 'Content matches blocklist',
                    'position': 0,
                    'threat_level': ThreatLevel.BLOCKED.value
                }],
                score=1.0,
                message="Content is blocklisted",
                pattern_version=pv,
            )
            self._dispatch_hooks(result, text)
            self._notify_integrations(result, source_id)
            return result
        
        # Check against patterns (both original and normalized text)
        # Track which matches came from original vs normalized
        matches = self.pattern_matcher.check_injection_patterns(text)
        original_match_count = len(matches)
        
        # Also check normalized text for evasion attempts
        if normalized_text != text:
            normalized_matches = self.pattern_matcher.check_injection_patterns(normalized_text)
            # Add matches found only in normalized form (evasion detected)
            # Dedup by position range to avoid inflating score
            existing_ranges = {(m[2], m[2] + len(m[0])) for m in matches}
            for match_text, threat_level, pos in normalized_matches:
                match_range = (pos, pos + len(match_text))
                # Skip if overlapping with an existing match
                overlaps = any(
                    not (match_range[1] <= er[0] or match_range[0] >= er[1])
                    for er in existing_ranges
                )
                if not overlaps:
                    matches.append((match_text, threat_level, pos))
                    existing_ranges.add(match_range)
        
        # Check custom patterns
        for pattern, threat_level in self.custom_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                for match in compiled.finditer(text):
                    matches.append((match.group(), threat_level, match.start()))
            except re.error:
                continue
        
        # Calculate score and determine threat level
        score = self._calculate_score(matches, len(text))
        suspicious_threshold, blocked_threshold = self._get_sensitivity_thresholds()
        
        # Determine final threat level
        if score >= blocked_threshold or any(match[1] == ThreatLevel.BLOCKED for match in matches):
            threat_level = ThreatLevel.BLOCKED
        elif score >= suspicious_threshold or any(match[1] == ThreatLevel.SUSPICIOUS for match in matches):
            threat_level = ThreatLevel.SUSPICIOUS  
        else:
            threat_level = ThreatLevel.SAFE
        
        # Format matches for result
        formatted_matches = []
        for i, (match_text, match_threat_level, position) in enumerate(matches):
            formatted_matches.append({
                'type': 'pattern_match',
                'text': match_text,
                'position': position,
                'threat_level': match_threat_level.value,
                'source': 'original' if i < original_match_count else 'normalized',
            })
        
        # Generate message
        if threat_level == ThreatLevel.BLOCKED:
            message = f"Input blocked: {len(matches)} high-risk patterns detected"
        elif threat_level == ThreatLevel.SUSPICIOUS:
            message = f"Input flagged: {len(matches)} suspicious patterns detected"
        else:
            message = "Input appears safe"
        
        result = GuardResult(
            threat_level=threat_level,
            is_safe=threat_level == ThreatLevel.SAFE,
            is_suspicious=threat_level == ThreatLevel.SUSPICIOUS,
            is_blocked=threat_level == ThreatLevel.BLOCKED,
            matches=formatted_matches,
            score=score,
            message=message,
            pattern_version=pv,
        )
        self._record_stat(result, text)
        self._dispatch_hooks(result, text)
        self._notify_integrations(result, source_id)
        return result

    # ------------------------------------------------------------------
    # Integration notifiers
    # ------------------------------------------------------------------

    def _notify_integrations(self, result: 'GuardResult', source_id: Optional[str]) -> None:
        """Notify optional BehaviorAnalyzer / ReputationTracker after analysis."""
        sid = source_id or "_default"
        threat_str = result.threat_level.value  # "safe", "suspicious", or "blocked"

        if self.behavior_analyzer is not None:
            try:
                pattern_types = list({
                    m.get('type', 'unknown') for m in result.matches
                })
                self.behavior_analyzer.record(
                    sid,
                    threat_str,
                    matched_patterns=pattern_types,
                    score=result.score,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("BehaviorAnalyzer.record raised: %s", exc)

        if self.reputation_tracker is not None:
            try:
                self.reputation_tracker.record_interaction(
                    sid,
                    threat_str,
                    was_blocked=result.is_blocked,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("ReputationTracker.record_interaction raised: %s", exc)

    # ------------------------------------------------------------------
    # Internal helpers (Sprint 4)
    # ------------------------------------------------------------------

    def _record_stat(self, result: 'GuardResult', text: str) -> None:  # noqa: ARG002
        """Record a lightweight stat entry for :meth:`get_pattern_stats`."""
        if result.threat_level == ThreatLevel.SAFE:
            risk = "low"
        elif result.threat_level == ThreatLevel.SUSPICIOUS:
            risk = "medium"
        else:
            risk = "high"

        pattern_types = list({
            m.get('type', 'unknown') for m in result.matches
        })

        entry: Dict[str, Any] = {
            'timestamp': time.time(),
            'blocked': result.is_blocked,
            'patterns': pattern_types,
            'risk': risk,
        }

        self._analysis_stats.append(entry)
        # Keep memory bounded
        if len(self._analysis_stats) > self._stats_max:
            self._analysis_stats = self._analysis_stats[-self._stats_max:]

    # ------------------------------------------------------------------
    # Security posture scoring (Sprint 4)
    # ------------------------------------------------------------------

    def security_posture_score(self) -> Dict[str, Any]:
        """
        Score the current security configuration posture.

        Returns a dict with keys:

        * ``score``            — float 0-1, higher = more secure
        * ``level``            — ``"low"``, ``"medium"``, ``"high"``, or ``"critical"``
        * ``components``       — per-component scores
        * ``recommendations``  — list of improvement suggestions
        """
        components: Dict[str, float] = {}
        recommendations: List[str] = []

        # ---- Rate limiting component ----
        if self.policy is not None:
            from .policy import RateLimitPolicy, CompositePolicy

            def _has_rate_limit(p) -> bool:
                if isinstance(p, RateLimitPolicy):
                    return True
                if isinstance(p, CompositePolicy):
                    return any(_has_rate_limit(child) for child in p.policies)
                return False

            components['rate_limiting'] = 1.0 if _has_rate_limit(self.policy) else 0.5
        else:
            components['rate_limiting'] = 0.3
            recommendations.append("Attach a RateLimitPolicy to guard against flooding attacks.")

        # ---- Content filtering component ----
        if self.policy is not None:
            from .policy import ContentFilterPolicy, CompositePolicy

            def _has_content_filter(p, ftype=None) -> bool:
                if isinstance(p, ContentFilterPolicy):
                    return ftype is None or p.filter_type in (ftype, "all")
                if isinstance(p, CompositePolicy):
                    return any(_has_content_filter(child, ftype) for child in p.policies)
                return False

            has_pii = _has_content_filter(self.policy, "pii")
            has_injection = _has_content_filter(self.policy, "injection")
            cf_score = sum([has_pii * 0.5, has_injection * 0.5])
            components['content_filtering'] = max(0.4, cf_score)
            if not has_pii:
                recommendations.append("Consider enabling a PII ContentFilterPolicy.")
            if not has_injection:
                recommendations.append("Consider enabling an injection ContentFilterPolicy.")
        else:
            # Pattern matching still runs, partial credit
            components['content_filtering'] = 0.6
            recommendations.append("Attach a ContentFilterPolicy for PII and injection coverage.")

        # ---- Pattern-based analysis ----
        pattern_count = len(self.pattern_matcher.injection_patterns)
        if pattern_count >= 50:
            components['pattern_analysis'] = 1.0
        elif pattern_count >= 20:
            components['pattern_analysis'] = 0.75
        else:
            components['pattern_analysis'] = 0.4
            recommendations.append("Use AGGRESSIVE_INJECTION_PATTERNS for higher pattern coverage.")

        # ---- Sensitivity level ----
        sensitivity_scores = {
            SensitivityLevel.STRICT: 1.0,
            SensitivityLevel.BALANCED: 0.75,
            SensitivityLevel.PERMISSIVE: 0.4,
        }
        components['sensitivity'] = sensitivity_scores.get(self.sensitivity, 0.5)
        if self.sensitivity == SensitivityLevel.PERMISSIVE:
            recommendations.append("Consider switching from PERMISSIVE to BALANCED sensitivity.")

        # ---- Behavioral analysis (hooks) ----
        if self._hooks.get('on_blocked'):
            components['behavioral_analysis'] = 0.85
        else:
            components['behavioral_analysis'] = 0.5
            recommendations.append(
                "Register an on_blocked hook to integrate behavioral analysis."
            )

        # ---- Aggregate ----
        weights = {
            'rate_limiting': 0.20,
            'content_filtering': 0.25,
            'pattern_analysis': 0.25,
            'sensitivity': 0.15,
            'behavioral_analysis': 0.15,
        }
        score = sum(components[k] * weights[k] for k in weights)
        score = round(min(1.0, max(0.0, score)), 3)

        if score >= 0.85:
            level = "critical"   # critical = maximally secure
        elif score >= 0.65:
            level = "high"
        elif score >= 0.40:
            level = "medium"
        else:
            level = "low"

        return {
            'score': score,
            'level': level,
            'components': {k: round(v, 3) for k, v in components.items()},
            'recommendations': recommendations,
        }

    # ------------------------------------------------------------------
    # Pattern stats dashboard (Sprint 4)
    # ------------------------------------------------------------------

    def get_pattern_stats(self, since_hours: float = 24) -> Dict[str, Any]:
        """
        Return attack-pattern statistics suitable for a security dashboard.

        Uses the in-memory analysis history tracked by :meth:`analyze`.
        If you need persistent stats across restarts, enable
        :class:`~antaris_guard.audit.AuditLogger` and query it separately.

        Args:
            since_hours: How far back to look (default 24 h).

        Returns a dict with::

            {
                "total_analyzed": int,
                "blocked":        int,
                "allowed":        int,
                "top_patterns":   [{"pattern": str, "count": int, "blocked": int}, ...],
                "risk_distribution": {"low": int, "medium": int, "high": int},
                "since_hours":    float,
                "note":           str | None,   # present when audit logging not used
            }
        """
        cutoff = time.time() - since_hours * 3600
        window = [e for e in self._analysis_stats if e['timestamp'] >= cutoff]

        total = len(window)
        blocked_count = sum(1 for e in window if e['blocked'])
        allowed_count = total - blocked_count

        # Pattern frequency table
        pattern_counts: Dict[str, int] = {}
        pattern_blocked: Dict[str, int] = {}
        for entry in window:
            for pat in entry.get('patterns', []):
                pattern_counts[pat] = pattern_counts.get(pat, 0) + 1
                if entry['blocked']:
                    pattern_blocked[pat] = pattern_blocked.get(pat, 0) + 1

        top_patterns = [
            {
                'pattern': pat,
                'count': cnt,
                'blocked': pattern_blocked.get(pat, 0),
            }
            for pat, cnt in sorted(
                pattern_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]
        ]

        risk_dist = {'low': 0, 'medium': 0, 'high': 0}
        for entry in window:
            risk = entry.get('risk', 'low')
            risk_dist[risk] = risk_dist.get(risk, 0) + 1

        return {
            'total_analyzed': total,
            'blocked': blocked_count,
            'allowed': allowed_count,
            'top_patterns': top_patterns,
            'risk_distribution': risk_dist,
            'since_hours': since_hours,
            'note': (
                "Stats are in-memory only and reset on process restart. "
                "Enable AuditLogger for persistent cross-session stats."
            ),
        }

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def is_safe(self, text: str) -> bool:
        """Quick check if text is safe to process."""
        result = self.analyze(text)
        return result.is_safe

    # ------------------------------------------------------------------
    # Sprint 2.5 — Stateful conversation-level policy integration
    # ------------------------------------------------------------------

    def add_stateful_policy(self, policy: "StatefulPolicy") -> None:
        """
        Attach a stateful conversation-level policy.

        When a stateful policy is attached, :meth:`check` evaluates it
        before the standard pattern scan.  If the policy denies the
        request, :meth:`check` returns an immediately blocked result.

        Parameters
        ----------
        policy:
            A :class:`~antaris_guard.policies.StatefulPolicy` (or
            composite) instance.
        """
        self.stateful_policy = policy

    def check(
        self,
        text: str,
        conversation_id: str = "_default",
        source_id: Optional[str] = None,
        cost: float = 0.0,
    ) -> "GuardResult":
        """
        Analyze text with stateful conversation context.

        This is the Sprint 2.5 entry point.  It layers stateful
        conversation policies on top of the existing :meth:`analyze`
        logic:

        1. Run pattern-based :meth:`analyze` to get a :class:`GuardResult`.
        2. If a :attr:`stateful_policy` is attached, call
           :meth:`~antaris_guard.policies.StatefulPolicy.evaluate_with_context`
           with the conversation context.
        3. If the stateful policy denies, return a BLOCKED result.
        4. If an :attr:`audit_logger` is attached, record the policy
           decision.

        Parameters
        ----------
        text:
            Input text to analyze.
        conversation_id:
            Conversation this message belongs to (default: ``"_default"``).
        source_id:
            Optional source/user identifier forwarded to :meth:`analyze`.
        cost:
            Optional USD cost estimate for this request (forwarded to
            stateful policies).

        Returns
        -------
        GuardResult
        """
        # Standard pattern analysis first
        guard_result = self.analyze(text, source_id=source_id)

        # Stateful policy evaluation (if attached)
        if self.stateful_policy is not None:
            from .policies import StatefulPolicyResult
            threat_level_str = guard_result.threat_level.value  # "safe"/"suspicious"/"blocked"

            sp_result = self.stateful_policy.evaluate_with_context(
                text=text,
                conversation_id=conversation_id,
                threat_level=threat_level_str,
                score=guard_result.score,
                cost=cost,
            )

            # Audit log the decision
            if self.audit_logger is not None:
                try:
                    self.audit_logger.log_policy_decision(
                        conversation_id=conversation_id,
                        policy_name=sp_result.policy_name,
                        decision="deny" if not sp_result.allowed else "allow",
                        reason=sp_result.reason,
                        evidence=sp_result.evidence,
                        source_id=source_id,
                        text_sample=text,
                    )
                except Exception as exc:
                    logger.warning("audit_logger.log_policy_decision raised: %s", exc)

            if not sp_result.allowed:
                pv = self.pattern_matcher.pattern_version
                blocked_result = GuardResult(
                    threat_level=ThreatLevel.BLOCKED,
                    is_safe=False,
                    is_suspicious=False,
                    is_blocked=True,
                    matches=[{
                        "type": "stateful_policy",
                        "policy_name": sp_result.policy_name,
                        "text": sp_result.reason,
                        "position": 0,
                        "threat_level": ThreatLevel.BLOCKED.value,
                        "confidence": sp_result.confidence,
                        "evidence": sp_result.evidence,
                    }],
                    score=1.0,
                    message=f"Stateful policy denied: {sp_result.reason}",
                    pattern_version=pv,
                )
                self._record_stat(blocked_result, text)
                self._dispatch_hooks(blocked_result, text)
                self._notify_integrations(blocked_result, source_id)
                return blocked_result

        return guard_result

    def get_stats(self) -> Dict[str, Any]:
        """Get current guard statistics and configuration."""
        return {
            'sensitivity': self.sensitivity,
            'pattern_count': len(self.pattern_matcher.injection_patterns),
            'pattern_version': self.pattern_matcher.pattern_version,
            'allowlist_size': len(self.allowlist),
            'blocklist_size': len(self.blocklist),
            'custom_patterns': len(self.custom_patterns),
            'hooks': {k: len(v) for k, v in self._hooks.items()},
            'policy': self.policy.name if self.policy is not None else None,
        }

    # ------------------------------------------------------------------
    # Policy file support (Sprint 10)
    # ------------------------------------------------------------------

    @property
    def policy_version(self) -> str:
        """
        Version string of the currently active policy.

        When a :attr:`policy` was supplied directly (not via a file) the
        version is taken from :attr:`policy.version` when available.
        When loaded from a file the top-level ``"version"`` key is used,
        or the policy's own ``version`` attribute as fallback.
        """
        if self._policy_version != "0":
            return self._policy_version
        if self.policy is not None and hasattr(self.policy, "version"):
            return str(self.policy.version)
        return "0"

    def reload_policy(self) -> None:
        """
        (Re-)load the policy from :attr:`_policy_file`.

        Does nothing when no ``policy_file`` was provided.

        Raises
        ------
        FileNotFoundError
            If the policy file does not exist.
        ValueError
            If the file contains invalid JSON or an unknown policy type.
        """
        if not self._policy_file:
            return

        with open(self._policy_file, "r") as fh:
            data = json.load(fh)

        # Extract optional top-level "version" before dispatching
        version = str(data.get("version", "1.0"))

        from .policy import BasePolicy
        self.policy = BasePolicy.from_dict(data)
        self._policy_version = version
        try:
            self._policy_file_mtime = os.path.getmtime(self._policy_file)
        except OSError:
            self._policy_file_mtime = time.time()

        logger.info("Policy reloaded from %s (version=%s)", self._policy_file, version)

    def _start_policy_watcher(self) -> None:
        """Start background thread that reloads policy when file changes."""
        self._policy_watch_stop.clear()

        def _loop():
            while not self._policy_watch_stop.is_set():
                try:
                    mtime = os.path.getmtime(self._policy_file)
                    if mtime != self._policy_file_mtime:
                        logger.info(
                            "Policy file changed, reloading: %s", self._policy_file
                        )
                        try:
                            self.reload_policy()
                        except Exception as exc:  # noqa: BLE001
                            logger.warning("Failed to reload policy: %s", exc)
                except OSError:
                    pass
                self._policy_watch_stop.wait(timeout=1.0)

        self._policy_watch_thread = threading.Thread(
            target=_loop,
            name="antaris-guard-policy-watcher",
            daemon=True,
        )
        self._policy_watch_thread.start()

    def stop_policy_watcher(self) -> None:
        """Stop the background policy-file watcher thread (if running)."""
        self._policy_watch_stop.set()

    # ------------------------------------------------------------------
    # Compliance audit report (Sprint 10)
    # ------------------------------------------------------------------

    def generate_compliance_report(
        self,
        framework: str = "SOC2",
        since_hours: float = 24,
    ) -> Dict[str, Any]:
        """
        Generate a compliance audit report from the in-memory stats.

        Parameters
        ----------
        framework:
            One of ``"SOC2"``, ``"HIPAA"``, ``"GDPR"``, ``"PCI_DSS"``.
        since_hours:
            How far back to look (default 24 h).

        Returns
        -------
        dict with keys::

            {
                "framework": str,
                "period_hours": float,
                "compliant": bool,
                "findings": list,
                "stats": {
                    "pii_blocks": int,
                    "rate_limit_blocks": int,
                    "injection_blocks": int,
                    "total_analyzed": int,
                    "total_blocked": int,
                },
                "recommendations": list,
            }
        """
        stats = self.get_pattern_stats(since_hours=since_hours)

        findings: List[Dict[str, Any]] = []
        recommendations: List[str] = []

        total_analyzed = stats["total_analyzed"]
        total_blocked = stats["blocked"]

        # Derive granular block counts from top_patterns entries
        pii_blocks = 0
        rate_limit_blocks = 0
        injection_blocks = 0

        for pat in stats.get("top_patterns", []):
            pname = pat.get("pattern", "")
            cnt = pat.get("blocked", 0)
            if "pii" in pname or "content_filter" in pname:
                pii_blocks += cnt
            elif "rate_limit" in pname:
                rate_limit_blocks += cnt
            elif pname in ("pattern_match", "injection"):
                injection_blocks += cnt

        # If we can't decompose from pattern labels, use heuristics
        if total_blocked > 0 and pii_blocks == 0 and injection_blocks == 0:
            injection_blocks = total_blocked

        # Framework-specific compliance checks
        framework_upper = framework.upper().replace("-", "_")

        if framework_upper == "HIPAA":
            # HIPAA: PII / PHI protection is mandatory
            if self.policy is None:
                findings.append({
                    "severity": "critical",
                    "rule": "HIPAA §164.312(a)",
                    "description": "No policy attached — PHI may flow unfiltered.",
                })
                recommendations.append(
                    "Apply ComplianceTemplate.HIPAA() to this guard instance."
                )
            else:
                from .policy import ContentFilterPolicy, CompositePolicy

                def _has_pii(p) -> bool:
                    if isinstance(p, ContentFilterPolicy):
                        return p.filter_type in ("pii", "all")
                    if isinstance(p, CompositePolicy):
                        return any(_has_pii(child) for child in p.policies)
                    return False

                if not _has_pii(self.policy):
                    findings.append({
                        "severity": "high",
                        "rule": "HIPAA §164.312(a)",
                        "description": "No PII ContentFilterPolicy found in attached policy.",
                    })
                    recommendations.append(
                        "Add ContentFilterPolicy(filter_type='pii') to your HIPAA policy."
                    )

        elif framework_upper == "GDPR":
            if self.policy is None:
                findings.append({
                    "severity": "high",
                    "rule": "GDPR Art. 5 — Data minimisation",
                    "description": "No policy attached — personal data may be processed unfiltered.",
                })
                recommendations.append(
                    "Apply ComplianceTemplate.GDPR() to this guard instance."
                )

        elif framework_upper == "PCI_DSS":
            if self.policy is None:
                findings.append({
                    "severity": "critical",
                    "rule": "PCI DSS Req. 3",
                    "description": "No policy attached — cardholder data unprotected.",
                })
                recommendations.append(
                    "Apply ComplianceTemplate.PCI_DSS() to this guard instance."
                )

        elif framework_upper == "SOC2":
            if self.policy is None:
                findings.append({
                    "severity": "medium",
                    "rule": "SOC 2 CC6.1",
                    "description": (
                        "No policy attached — consider adding rate limiting and "
                        "content filtering."
                    ),
                })
                recommendations.append(
                    "Apply ComplianceTemplate.SOC2() for standard SOC 2 controls."
                )

        compliant = len([f for f in findings if f["severity"] in ("high", "critical")]) == 0

        return {
            "framework": framework_upper,
            "period_hours": since_hours,
            "compliant": compliant,
            "findings": findings,
            "stats": {
                "pii_blocks": pii_blocks,
                "rate_limit_blocks": rate_limit_blocks,
                "injection_blocks": injection_blocks,
                "total_analyzed": total_analyzed,
                "total_blocked": total_blocked,
            },
            "recommendations": recommendations,
        }