"""
PromptGuard - Main security class for analyzing input text and detecting injection attempts.
"""
import json
import logging
import os
import re
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from .patterns import PatternMatcher, ThreatLevel
from .normalizer import normalize
from .utils import atomic_write_json

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
                 sensitivity: str = SensitivityLevel.BALANCED):
        """
        Initialize PromptGuard.
        
        Args:
            config_path: Path to JSON configuration file
            sensitivity: Sensitivity level (strict/balanced/permissive)
        """
        self.sensitivity = sensitivity
        self.pattern_matcher = PatternMatcher()
        self.allowlist: Set[str] = set()
        self.blocklist: Set[str] = set()
        self.custom_patterns: List[tuple] = []
        
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
        except (json.JSONDecodeError, KeyError) as e:
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
    
    def _check_allowlist(self, text: str) -> bool:
        """Check if text is in allowlist."""
        text_lower = text.lower().strip()
        return any(allowed in text_lower for allowed in self.allowlist)
    
    def _check_blocklist(self, text: str) -> bool:
        """Check if text is in blocklist.""" 
        text_lower = text.lower().strip()
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
    
    def analyze(self, text: str) -> GuardResult:
        """
        Analyze text for potential security threats.
        
        Args:
            text: Input text to analyze
            
        Returns:
            GuardResult with threat assessment
        """
        if not text or not text.strip():
            return GuardResult(
                threat_level=ThreatLevel.SAFE,
                is_safe=True,
                is_suspicious=False,
                is_blocked=False,
                matches=[],
                score=0.0,
                message="Empty input"
            )
        
        text = text.strip()
        
        # Normalize for evasion resistance
        normalized_text, _ = normalize(text)
        
        # Check allowlist first
        if self._check_allowlist(text):
            return GuardResult(
                threat_level=ThreatLevel.SAFE,
                is_safe=True,
                is_suspicious=False,
                is_blocked=False,
                matches=[],
                score=0.0,
                message="Allowlisted content"
            )
        
        # Check blocklist
        if self._check_blocklist(text):
            return GuardResult(
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
                message="Content is blocklisted"
            )
        
        # Check against patterns (both original and normalized text)
        matches = self.pattern_matcher.check_injection_patterns(text)
        
        # Also check normalized text for evasion attempts
        if normalized_text != text:
            normalized_matches = self.pattern_matcher.check_injection_patterns(normalized_text)
            # Add matches found only in normalized form (evasion detected)
            existing_threats = {m[0].lower() for m in matches}
            for match_text, threat_level, pos in normalized_matches:
                if match_text.lower() not in existing_threats:
                    matches.append((match_text, threat_level, pos))
        
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
        for match_text, match_threat_level, position in matches:
            formatted_matches.append({
                'type': 'pattern_match',
                'text': match_text,
                'position': position,
                'threat_level': match_threat_level.value
            })
        
        # Generate message
        if threat_level == ThreatLevel.BLOCKED:
            message = f"Input blocked: {len(matches)} high-risk patterns detected"
        elif threat_level == ThreatLevel.SUSPICIOUS:
            message = f"Input flagged: {len(matches)} suspicious patterns detected"
        else:
            message = "Input appears safe"
        
        return GuardResult(
            threat_level=threat_level,
            is_safe=threat_level == ThreatLevel.SAFE,
            is_suspicious=threat_level == ThreatLevel.SUSPICIOUS,
            is_blocked=threat_level == ThreatLevel.BLOCKED,
            matches=formatted_matches,
            score=score,
            message=message
        )
    
    def is_safe(self, text: str) -> bool:
        """Quick check if text is safe to process."""
        result = self.analyze(text)
        return result.is_safe
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current guard statistics and configuration."""
        return {
            'sensitivity': self.sensitivity,
            'pattern_count': len(self.pattern_matcher.injection_patterns),
            'allowlist_size': len(self.allowlist),
            'blocklist_size': len(self.blocklist),
            'custom_patterns': len(self.custom_patterns)
        }