"""
Source reputation scoring — build trust profiles per source over time.

Tracks interaction history and adjusts threat assessment based on
accumulated behavior. The same input gets different treatment depending
on the source's trust level.

All deterministic, zero dependencies, file-based persistence.
"""

import json
import logging
import os
import time
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, asdict
from .utils import atomic_write_json

logger = logging.getLogger(__name__)


@dataclass
class ReputationProfile:
    """Trust profile for a source."""
    source_id: str
    trust_score: float  # 0.0 (untrusted) to 1.0 (fully trusted)
    total_requests: int
    safe_requests: int
    suspicious_requests: int
    blocked_requests: int
    first_seen: float
    last_seen: float
    escalation_count: int  # Times trust was lowered due to bad behavior
    decay_applied: float  # Trust decay from inactivity
    last_blocked_time: float = 0.0  # Timestamp of most recent blocked event
    daily_safe_count: int = 0  # Safe boosts applied today
    daily_safe_reset: float = 0.0  # When daily counter was last reset


class ReputationTracker:
    """
    Track source reputation over time.
    
    New sources start at a configurable initial trust level. Trust increases
    with safe interactions and decreases with suspicious/blocked ones.
    Inactive sources decay toward the initial level over time.
    
    Features:
    - Per-source trust profiles with history
    - Configurable trust adjustment rates
    - Inactivity decay (sources that go quiet drift back to baseline)
    - Threshold-based automatic escalation
    - File-based persistence
    """
    
    # Trust adjustment amounts
    SAFE_BOOST = 0.02        # Small boost per safe request
    SUSPICIOUS_PENALTY = 0.10  # Moderate penalty per suspicious request
    BLOCKED_PENALTY = 0.25    # Large penalty per blocked request
    
    # Trust boundaries
    MIN_TRUST = 0.0
    MAX_TRUST = 1.0
    INITIAL_TRUST = 0.5
    
    # Inactivity decay
    DECAY_HALF_LIFE_HOURS = 168  # 1 week — trust drifts back to initial over time
    
    # Anti-farming: cooldown after blocked events (trust can't increase for N seconds)
    BLOCKED_COOLDOWN_SECONDS = 600  # 10 minutes
    
    # Anti-farming: max safe boosts per 24h period per source
    MAX_DAILY_SAFE_BOOSTS = 50  # After this, safe requests don't increase trust
    
    def __init__(self, store_path: str = "./reputation_store.json",
                 initial_trust: float = 0.5):
        """
        Initialize ReputationTracker.
        
        Args:
            store_path: Path to persistence file
            initial_trust: Starting trust for new sources (0.0-1.0)
        """
        self.store_path = store_path
        self.initial_trust = max(0.0, min(1.0, initial_trust))
        self.profiles: Dict[str, ReputationProfile] = {}
        self._load()
    
    def _load(self) -> None:
        """Load profiles from disk."""
        if not os.path.exists(self.store_path):
            return
        try:
            with open(self.store_path, 'r') as f:
                data = json.load(f)
            for source_id, profile_data in data.get('profiles', {}).items():
                self.profiles[source_id] = ReputationProfile(**profile_data)
        except (json.JSONDecodeError, TypeError, KeyError):
            pass
    
    def _save(self) -> None:
        """Save profiles to disk (atomic write)."""
        data = {
            'profiles': {sid: asdict(p) for sid, p in self.profiles.items()},
            'saved_at': time.time(),
        }
        try:
            atomic_write_json(self.store_path, data)
        except OSError:
            # atomic_write_json already logged the error
            pass
    
    def _get_or_create(self, source_id: str) -> ReputationProfile:
        """Get existing profile or create a new one."""
        if source_id not in self.profiles:
            now = time.time()
            self.profiles[source_id] = ReputationProfile(
                source_id=source_id,
                trust_score=self.initial_trust,
                total_requests=0,
                safe_requests=0,
                suspicious_requests=0,
                blocked_requests=0,
                first_seen=now,
                last_seen=now,
                escalation_count=0,
                decay_applied=0.0,
            )
        return self.profiles[source_id]
    
    def _apply_decay(self, profile: ReputationProfile) -> None:
        """
        Apply inactivity decay — trust drifts toward initial over time.
        
        NOTE: This mutates the profile in-memory but does NOT call _save().
        This is intentional — decay is idempotent and recalculated from
        last_seen on every call, so restarting the process and recalculating
        gives the same result. Only record_interaction() persists changes.
        """
        now = time.time()
        hours_inactive = (now - profile.last_seen) / 3600
        
        if hours_inactive < 1.0:
            return
        
        # Exponential decay toward initial trust
        decay_factor = 0.5 ** (hours_inactive / self.DECAY_HALF_LIFE_HOURS)
        diff = profile.trust_score - self.initial_trust
        decayed_diff = diff * decay_factor
        old_score = profile.trust_score
        profile.trust_score = self.initial_trust + decayed_diff
        profile.decay_applied += abs(old_score - profile.trust_score)
    
    def record_interaction(self, source_id: str, threat_level: str,
                          was_blocked: bool = False) -> ReputationProfile:
        """
        Record an interaction and update trust score.
        
        Args:
            source_id: Source identifier
            threat_level: "safe", "suspicious", or "blocked"
            was_blocked: Whether the request was actually blocked
            
        Returns:
            Updated ReputationProfile
        """
        profile = self._get_or_create(source_id)
        self._apply_decay(profile)
        
        now = time.time()
        profile.total_requests += 1
        profile.last_seen = now
        
        # Reset daily safe counter if 24h have elapsed
        if now - profile.daily_safe_reset > 86400:
            profile.daily_safe_count = 0
            profile.daily_safe_reset = now
        
        if threat_level == "safe":
            profile.safe_requests += 1
            # Anti-farming: no trust boost during blocked cooldown
            in_cooldown = (now - profile.last_blocked_time) < self.BLOCKED_COOLDOWN_SECONDS
            # Anti-farming: cap daily safe boosts
            at_daily_cap = profile.daily_safe_count >= self.MAX_DAILY_SAFE_BOOSTS
            
            if not in_cooldown and not at_daily_cap:
                profile.trust_score = min(
                    self.MAX_TRUST,
                    profile.trust_score + self.SAFE_BOOST
                )
                profile.daily_safe_count += 1
        elif threat_level == "suspicious":
            profile.suspicious_requests += 1
            profile.trust_score = max(
                self.MIN_TRUST,
                profile.trust_score - self.SUSPICIOUS_PENALTY
            )
        elif threat_level == "blocked":
            profile.blocked_requests += 1
            profile.trust_score = max(
                self.MIN_TRUST,
                profile.trust_score - self.BLOCKED_PENALTY
            )
            profile.escalation_count += 1
            profile.last_blocked_time = now
        
        self._save()
        return profile
    
    def get_trust(self, source_id: str) -> float:
        """
        Get current trust score for a source.
        
        Returns initial_trust for unknown sources.
        """
        if source_id not in self.profiles:
            return self.initial_trust
        
        profile = self.profiles[source_id]
        self._apply_decay(profile)
        return profile.trust_score
    
    def get_profile(self, source_id: str) -> Optional[ReputationProfile]:
        """Get full reputation profile for a source."""
        if source_id not in self.profiles:
            return None
        profile = self.profiles[source_id]
        self._apply_decay(profile)
        return profile
    
    def adjust_thresholds(self, source_id: str, 
                         suspicious_threshold: float,
                         blocked_threshold: float) -> tuple:
        """
        Adjust detection thresholds based on source reputation.
        
        Trusted sources get higher thresholds (more lenient).
        Untrusted sources get lower thresholds (more strict).
        
        Anti-gaming ratchet: sources that have EVER been blocked cannot
        receive above-baseline leniency, regardless of current trust.
        This prevents the attack where an adversary builds trust with
        safe requests then exploits the higher thresholds.
        
        Args:
            source_id: Source identifier
            suspicious_threshold: Base suspicious threshold
            blocked_threshold: Base blocked threshold
            
        Returns:
            Tuple of (adjusted_suspicious, adjusted_blocked)
        """
        trust = self.get_trust(source_id)
        profile = self.profiles.get(source_id)
        
        # Trust adjustment: ±20% of threshold based on trust deviation from 0.5
        trust_offset = (trust - 0.5) * 0.4  # -0.2 to +0.2
        
        # Anti-gaming ratchet: sources with any escalation history
        # cannot get above-baseline leniency (positive offset capped at 0)
        if profile and profile.escalation_count > 0:
            trust_offset = min(0.0, trust_offset)
        
        adjusted_suspicious = max(0.05, min(0.95, suspicious_threshold + trust_offset))
        adjusted_blocked = max(0.1, min(1.0, blocked_threshold + trust_offset))
        
        # Ensure blocked threshold stays above suspicious threshold
        adjusted_blocked = max(adjusted_blocked, adjusted_suspicious + 0.05)
        
        return adjusted_suspicious, adjusted_blocked
    
    def get_high_risk_sources(self, max_trust: float = 0.2) -> List[ReputationProfile]:
        """Get sources with trust below threshold."""
        results = []
        for profile in self.profiles.values():
            self._apply_decay(profile)
            if profile.trust_score <= max_trust:
                results.append(profile)
        return sorted(results, key=lambda p: p.trust_score)
    
    def reset_source(self, source_id: str) -> None:
        """
        Reset a source's reputation to initial trust.
        
        SECURITY-SENSITIVE: This clears escalation_count, which removes
        the anti-gaming ratchet for this source. Only expose through
        admin/privileged APIs — never allow untrusted callers to trigger.
        """
        if source_id in self.profiles:
            profile = self.profiles[source_id]
            profile.trust_score = self.initial_trust
            profile.escalation_count = 0
            profile.decay_applied = 0.0
            self._save()
    
    def remove_source(self, source_id: str) -> bool:
        """
        Remove a source's profile entirely.
        
        SECURITY-SENSITIVE: A removed source re-enters as a fresh profile
        with initial trust and no escalation history, bypassing the
        anti-gaming ratchet. Only expose through admin/privileged APIs.
        """
        if source_id in self.profiles:
            del self.profiles[source_id]
            self._save()
            return True
        return False
    
    def stats(self) -> Dict[str, Any]:
        """Get tracker statistics (applies decay for current values)."""
        if not self.profiles:
            return {
                'total_sources': 0,
                'avg_trust': self.initial_trust,
                'high_risk_count': 0,
            }
        
        # Apply decay to get current trust values
        for profile in self.profiles.values():
            self._apply_decay(profile)
        trusts = [p.trust_score for p in self.profiles.values()]
        return {
            'total_sources': len(self.profiles),
            'avg_trust': sum(trusts) / len(trusts),
            'min_trust': min(trusts),
            'max_trust': max(trusts),
            'high_risk_count': sum(1 for t in trusts if t <= 0.2),
            'total_interactions': sum(p.total_requests for p in self.profiles.values()),
        }
