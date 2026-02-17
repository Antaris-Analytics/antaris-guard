"""
Detection patterns for prompt injection and PII identification.

Pattern versioning: Every pattern set has a version string (PATTERN_VERSION).
This version is included in GuardResult and audit events so you can trace
which ruleset flagged a given input, even after pattern updates.
"""
import re
from typing import Dict, List, Optional, Pattern, Tuple
from enum import Enum


# Bump this when patterns change — included in all match results
PATTERN_VERSION = "1.0.0"


class ThreatLevel(Enum):
    """Threat level classification for detected patterns."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


# Common prompt injection patterns
PROMPT_INJECTION_PATTERNS = [
    # System prompt overrides
    (r"(?i)ignore\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|prompts?|rules?)", ThreatLevel.BLOCKED),
    (r"(?i)forget\s+(?:everything|all\s+previous|your\s+instructions)", ThreatLevel.BLOCKED),
    (r"(?i)(?:system\s*:|assistant\s*:|user\s*:)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:new\s+)?(?:system\s+)?(?:prompt|instruction):\s*", ThreatLevel.SUSPICIOUS),
    
    # Role confusion attempts
    (r"(?i)you\s+are\s+(?:now\s+)?(?:a|an)\s+(?:different|new|helpful|unrestricted)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:act|behave|pretend)\s+(?:as|like|that)\s+(?:if\s+)?you\s+(?:are|were)", ThreatLevel.SUSPICIOUS),
    (r"(?i)roleplay\s+(?:as|that)\s+(?:you\s+)?(?:a|an)?\s*(?:malicious|evil|hacker)", ThreatLevel.SUSPICIOUS),
    (r"(?i)imagine\s+(?:that\s+)?you\s+(?:are|were)", ThreatLevel.SUSPICIOUS),
    
    # Developer mode attempts (catch activations, not mentions in context)
    (r"(?i)(?:enable|activate|enter|switch\s+to|turn\s+on)\s+developer\s+mode", ThreatLevel.BLOCKED),
    (r"(?i)developer\s+mode\s+(?:activated|enabled|on)", ThreatLevel.BLOCKED),
    (r"(?i)(?:enable|activate|enter|switch\s+to|turn\s+on)\s+debug\s+mode", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:enable|activate|enter|switch\s+to|turn\s+on)\s+god\s+mode", ThreatLevel.BLOCKED),
    (r"(?i)god\s+mode\s+(?:activated|enabled|on)", ThreatLevel.BLOCKED),
    (r"(?i)(?:enable|activate|enter|switch\s+to|turn\s+on)\s+admin\s+mode", ThreatLevel.BLOCKED),
    
    # Jailbreak attempts
    (r"(?i)dan\s+mode", ThreatLevel.BLOCKED),  # "Do Anything Now"
    (r"(?i)jailbreak", ThreatLevel.BLOCKED),
    (r"(?i)break\s+(?:out\s+of|free\s+from|your)", ThreatLevel.BLOCKED),
    (r"(?i)escape\s+your\s+(?:programming|constraints)", ThreatLevel.BLOCKED),
    
    # Direct command attempts (imperative form — "execute this command", not "my code uses exec")
    (r"(?i)execute\s+(?:this\s+)?(?:command|code|script)", ThreatLevel.BLOCKED),
    (r"(?i)run\s+(?:this\s+)?(?:command|code|script)\b", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:please\s+)?eval\s*\([^)]*\)", ThreatLevel.BLOCKED),
    (r"(?i)(?:please\s+)?exec\s*\([^)]*\)", ThreatLevel.BLOCKED),
    
    # Information extraction attempts
    (r"(?i)(?:show|reveal)\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions)", ThreatLevel.BLOCKED),
    (r"(?i)tell\s+me\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|internal\s+rules)", ThreatLevel.SUSPICIOUS),
    (r"(?i)what\s+(?:are\s+)?your\s+(?:system\s+)?(?:instructions|rules|internal\s+rules)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:dump|export|print)\s+(?:your\s+)?(?:memory|context|history|system\s+configuration)", ThreatLevel.BLOCKED),
    
    # Boundary testing
    (r"(?i)test\s+your\s+(?:limits|boundaries|restrictions)", ThreatLevel.SUSPICIOUS),
    (r"(?i)what\s+(?:can't|cannot)\s+you\s+do\b(?!\s+(?:with|in|about|for|using|to)\b)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:bypass|circumvent|override)\s+(?:your\s+)?(?:safety|security|filters|restrictions)", ThreatLevel.BLOCKED),
    
    # Social engineering patterns
    (r"(?i)urgent\s*:?\s*(?:emergency|help|assistance|life\s+threatening)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:life\s+or\s+death|matter\s+of\s+life)", ThreatLevel.SUSPICIOUS),
    (r"(?i)my\s+(?:boss|manager|teacher)\s+(?:said|told|asked)", ThreatLevel.SUSPICIOUS),
    
    # Code injection patterns
    (r"(?i)<script[^>]*>", ThreatLevel.BLOCKED),
    (r"(?i)javascript\s*:", ThreatLevel.BLOCKED),
    (r"(?i)data\s*:\s*text/html", ThreatLevel.BLOCKED),
    (r"(?i)on(?:click|load|error|mouseover)\s*=", ThreatLevel.BLOCKED),
    
    # SQL injection patterns  
    (r"(?i)(?:union\s+(?:all\s+)?select|select\s+.*\s+from)", ThreatLevel.BLOCKED),
    (r"(?i)(?:drop\s+table|delete\s+from|insert\s+into)", ThreatLevel.BLOCKED),
    (r"(?i)(?:--|#|/\*)", ThreatLevel.SUSPICIOUS),  # SQL comment patterns
    
    # Template injection
    (r"\{\{.*\}\}", ThreatLevel.SUSPICIOUS),  # Jinja2/Django templates
    (r"\$\{.*\}", ThreatLevel.SUSPICIOUS),    # Various template engines
    (r"<%.*%>", ThreatLevel.SUSPICIOUS),     # ERB/ASP templates
    
    # Base64/encoded payloads (basic detection)
    (r"(?i)base64\s*[,:]", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:decode|decode64|atob|btoa)\s*\(", ThreatLevel.SUSPICIOUS),
    
    # Suspicious Unicode and encoding
    (r"\\u[0-9a-fA-F]{4}", ThreatLevel.SUSPICIOUS),  # Unicode escapes
    (r"\\x[0-9a-fA-F]{2}", ThreatLevel.SUSPICIOUS),  # Hex escapes
    (r"%[0-9a-fA-F]{2}", ThreatLevel.SUSPICIOUS),    # URL encoding
    
    # Indirect instruction patterns (conservative — in main set)
    (r"(?i)disregard\s+(?:your\s+)?(?:earlier|previous|above)", ThreatLevel.SUSPICIOUS),
    (r"(?i)from\s+now\s+on\s*,?\s+(?:you\s+)?(?:will|should|must)", ThreatLevel.SUSPICIOUS),
    (r"(?i)for\s+the\s+rest\s+of\s+(?:this\s+)?(?:chat|conversation|session)", ThreatLevel.SUSPICIOUS),
    
    # Concatenated forms (catch normalizer output where spaces are removed)
    # These fire on the normalized text when spacing/filler evasion collapses words
    (r"(?i)ignore\s*(?:all\s*)?(?:previous\s*)?(?:instructions|rules|prompts)", ThreatLevel.BLOCKED),
    (r"(?i)enable\s*developer\s*mode", ThreatLevel.BLOCKED),
    (r"(?i)enable\s*god\s*mode", ThreatLevel.BLOCKED),
    (r"(?i)enable\s*admin\s*mode", ThreatLevel.BLOCKED),
    (r"(?i)enable\s*debug\s*mode", ThreatLevel.SUSPICIOUS),
    (r"(?i)show\s*(?:me\s*)?your\s*system\s*prompt", ThreatLevel.BLOCKED),
    (r"(?i)reveal\s*(?:your\s*)?instructions", ThreatLevel.BLOCKED),
    (r"(?i)forget\s*everything", ThreatLevel.BLOCKED),
    (r"(?i)escape\s*your\s*programming", ThreatLevel.BLOCKED),
    (r"(?i)bypass\s*(?:your\s*)?safety", ThreatLevel.BLOCKED),
    (r"(?i)override\s*(?:your\s*)?restrictions", ThreatLevel.BLOCKED),
]


# PII detection patterns
PII_PATTERNS = [
    # Email addresses
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email"),
    
    # Phone numbers (various formats)
    (r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b", "phone"),
    (r"\b\d{3}-\d{3}-\d{4}\b", "phone"),
    (r"\b\(\d{3}\)\s?\d{3}-\d{4}\b", "phone"),
    
    # SSN patterns
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    (r"\b\d{3}\s\d{2}\s\d{4}\b", "ssn"),
    
    # Credit card patterns (basic detection)
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "credit_card"),
    
    # IP addresses
    (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "ip_address"),
    
    # Generic patterns for common PII
    (r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+", "credential"),
    (r"(?i)\bpassword\s+\S+", "credential"),
    (r"(?i)\b(?:api[_\s]?key|token|secret)\s*[:=]\s*\S+", "api_key"),
]


# Aggressive injection patterns — opt-in preset for higher security environments.
# These catch more indirect injection but have higher false positive rates.
# Use: PatternMatcher(injection_patterns=PROMPT_INJECTION_PATTERNS + AGGRESSIVE_INJECTION_PATTERNS)
AGGRESSIVE_INJECTION_PATTERNS = [
    # Indirect instruction overrides
    (r"(?i)(?:follow|obey|listen\s+to)\s+(?:my|these|the\s+following)\s+(?:rules|instructions|commands)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:instead\s+of|rather\s+than)\s+(?:your|the)\s+(?:original|earlier|previous|normal)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:the\s+above|earlier)\s+(?:policy|rules?|instructions?)\s+(?:don't|doesn't|do\s+not)\s+apply", ThreatLevel.SUSPICIOUS),
    (r"(?i)answer\s+(?:plainly|freely|honestly|without\s+restrictions)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:stop|cease|quit)\s+(?:being|acting)\s+(?:so\s+)?(?:restrictive|careful|cautious)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:remove|drop|lift|disable)\s+(?:all\s+)?(?:your\s+)?(?:restrictions|filters|safeguards|guardrails)", ThreatLevel.BLOCKED),
    (r"(?i)(?:speak|talk|respond)\s+(?:freely|without\s+(?:filters|restrictions|limits))", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:real|true|actual)\s+(?:answer|response|opinion)\s+(?:without|no)\s+(?:censorship|filters)", ThreatLevel.SUSPICIOUS),
    
    # Authority assertion patterns
    (r"(?i)(?:i\s+am|i'm)\s+(?:your|the)\s+(?:admin|administrator|developer|creator|owner)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:i\s+have|i've\s+got)\s+(?:admin|root|elevated|special)\s+(?:access|permissions?|privileges?)", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:authorized|permitted|allowed)\s+to\s+(?:access|see|view|modify)\s+(?:your|the|all)", ThreatLevel.SUSPICIOUS),
    
    # Output manipulation
    (r"(?i)(?:begin|start)\s+(?:your\s+)?(?:response|answer|reply)\s+with", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:output|print|write|say)\s+(?:exactly|only|just)\s*:", ThreatLevel.SUSPICIOUS),
    (r"(?i)(?:do\s+not|don't|never)\s+(?:mention|say|reveal|include)\s+(?:that|this|the\s+fact)", ThreatLevel.SUSPICIOUS),
]


class PatternMatcher:
    """
    Compiled pattern matcher for efficient regex operations.
    
    Supports configurable pattern sets: pass custom injection_patterns
    and/or pii_patterns to override the built-in defaults. Each matcher
    tracks its pattern_version for audit trail.
    """
    
    def __init__(self, injection_patterns: Optional[List[Tuple[str, ThreatLevel]]] = None,
                 pii_patterns: Optional[List[Tuple[str, str]]] = None,
                 version: Optional[str] = None):
        """
        Initialize PatternMatcher.
        
        Args:
            injection_patterns: Custom injection patterns as (regex_str, ThreatLevel) tuples.
                                Defaults to PROMPT_INJECTION_PATTERNS.
            pii_patterns: Custom PII patterns as (regex_str, pii_type) tuples.
                          Defaults to PII_PATTERNS.
            version: Pattern set version string. Defaults to PATTERN_VERSION.
        """
        self.pattern_version = version or PATTERN_VERSION
        self._raw_injection = injection_patterns if injection_patterns is not None else PROMPT_INJECTION_PATTERNS
        self._raw_pii = pii_patterns if pii_patterns is not None else PII_PATTERNS
        self.injection_patterns: List[Tuple[Pattern[str], ThreatLevel]] = []
        self.pii_patterns: List[Tuple[Pattern[str], str]] = []
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile all regex patterns for performance."""
        self.injection_patterns = []
        for pattern, threat_level in self._raw_injection:
            try:
                compiled = re.compile(pattern)
                self.injection_patterns.append((compiled, threat_level))
            except re.error:
                continue
                
        self.pii_patterns = []
        for pattern, pii_type in self._raw_pii:
            try:
                compiled = re.compile(pattern)
                self.pii_patterns.append((compiled, pii_type))
            except re.error:
                continue
    
    def check_injection_patterns(self, text: str) -> List[Tuple[str, ThreatLevel, int]]:
        """
        Check text against injection patterns.
        
        Returns:
            List of (matched_text, threat_level, position) tuples
        """
        matches = []
        for pattern, threat_level in self.injection_patterns:
            for match in pattern.finditer(text):
                matches.append((match.group(), threat_level, match.start()))
        return matches
    
    def check_pii_patterns(self, text: str) -> List[Tuple[str, str, int]]:
        """
        Check text against PII patterns.
        
        Returns:
            List of (matched_text, pii_type, position) tuples
        """
        matches = []
        for pattern, pii_type in self.pii_patterns:
            for match in pattern.finditer(text):
                matches.append((match.group(), pii_type, match.start()))
        return matches
    
    def get_highest_threat_level(self, text: str) -> ThreatLevel:
        """Get the highest threat level found in the text."""
        matches = self.check_injection_patterns(text)
        if not matches:
            return ThreatLevel.SAFE
            
        threat_levels = [match[1] for match in matches]
        
        if ThreatLevel.BLOCKED in threat_levels:
            return ThreatLevel.BLOCKED
        elif ThreatLevel.SUSPICIOUS in threat_levels:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.SAFE