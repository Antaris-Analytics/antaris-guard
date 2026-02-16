"""
ContentFilter - Output filtering and PII detection/redaction.
"""
import json
import os
import re
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass
from .patterns import PatternMatcher


@dataclass
class FilterResult:
    """Result of content filtering operation."""
    filtered_text: str
    detections: List[Dict[str, Any]]
    pii_found: bool
    original_text: str
    redaction_count: int


class ContentFilter:
    """
    Content filtering and PII detection/redaction.
    
    Features:
    - PII detection (emails, phones, SSNs, credit cards, etc.)
    - Configurable redaction masks
    - Output sanitization
    - Custom pattern support
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize ContentFilter.
        
        Args:
            config_path: Path to JSON configuration file
        """
        self.pattern_matcher = PatternMatcher()
        self.redaction_masks = self._default_masks()
        self.enabled_detections: Set[str] = set(['email', 'phone', 'ssn', 'credit_card', 'api_key', 'credential'])
        self.custom_patterns: List[Tuple[str, str]] = []
        self.redaction_enabled = True
        
        # Load configuration if provided
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
    
    def _default_masks(self) -> Dict[str, str]:
        """Default redaction masks for different PII types."""
        return {
            'email': '[EMAIL]',
            'phone': '[PHONE]', 
            'ssn': '[SSN]',
            'credit_card': '[CREDIT_CARD]',
            'ip_address': '[IP_ADDRESS]',
            'api_key': '[API_KEY]',
            'credential': '[CREDENTIAL]',
            'default': '[REDACTED]'
        }
    
    def _load_config(self, config_path: str) -> None:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Update redaction masks
            masks = config.get('redaction_masks', {})
            self.redaction_masks.update(masks)
            
            # Update enabled detections
            enabled = config.get('enabled_detections', [])
            if enabled:
                self.enabled_detections = set(enabled)
            
            # Load custom patterns
            custom_patterns = config.get('custom_patterns', [])
            for pattern_data in custom_patterns:
                pattern = pattern_data.get('pattern')
                pii_type = pattern_data.get('type', 'custom')
                if pattern:
                    self.custom_patterns.append((pattern, pii_type))
            
            # Redaction setting
            self.redaction_enabled = config.get('redaction_enabled', True)
                    
        except (json.JSONDecodeError, FileNotFoundError, KeyError):
            # Fail silently and use defaults
            pass
    
    def save_config(self, config_path: str) -> None:
        """Save current configuration to JSON file."""
        config = {
            'redaction_masks': self.redaction_masks,
            'enabled_detections': list(self.enabled_detections),
            'redaction_enabled': self.redaction_enabled,
            'custom_patterns': [
                {
                    'pattern': pattern,
                    'type': pii_type
                }
                for pattern, pii_type in self.custom_patterns
            ]
        }
        
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def set_redaction_mask(self, pii_type: str, mask: str) -> None:
        """Set custom redaction mask for a PII type."""
        self.redaction_masks[pii_type] = mask
    
    def enable_detection(self, pii_type: str) -> None:
        """Enable detection for a PII type."""
        self.enabled_detections.add(pii_type)
    
    def disable_detection(self, pii_type: str) -> None:
        """Disable detection for a PII type.""" 
        self.enabled_detections.discard(pii_type)
    
    def add_custom_pattern(self, pattern: str, pii_type: str) -> None:
        """Add a custom PII detection pattern."""
        self.custom_patterns.append((pattern, pii_type))
    
    def detect_pii(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect PII in text without redaction.
        
        Returns:
            List of detection dictionaries with details
        """
        detections = []
        
        # Check built-in patterns
        matches = self.pattern_matcher.check_pii_patterns(text)
        for match_text, pii_type, position in matches:
            if pii_type in self.enabled_detections:
                detections.append({
                    'type': pii_type,
                    'text': match_text,
                    'position': position,
                    'length': len(match_text),
                    'end_position': position + len(match_text)
                })
        
        # Check custom patterns
        for pattern, pii_type in self.custom_patterns:
            if pii_type in self.enabled_detections:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    for match in compiled.finditer(text):
                        detections.append({
                            'type': pii_type,
                            'text': match.group(),
                            'position': match.start(),
                            'length': len(match.group()),
                            'end_position': match.end()
                        })
                except re.error:
                    continue
        
        # Sort by position for consistent ordering
        detections.sort(key=lambda x: x['position'])
        return detections
    
    def redact_text(self, text: str, detections: Optional[List[Dict[str, Any]]] = None) -> str:
        """
        Redact PII in text using configured masks.
        
        Args:
            text: Input text
            detections: Pre-computed detections (will detect if not provided)
            
        Returns:
            Text with PII redacted
        """
        if not self.redaction_enabled:
            return text
            
        if detections is None:
            detections = self.detect_pii(text)
        
        if not detections:
            return text
        
        # Sort detections by position (reverse order to maintain positions during replacement)
        detections.sort(key=lambda x: x['position'], reverse=True)
        
        result_text = text
        for detection in detections:
            start = detection['position']
            end = detection['end_position']
            pii_type = detection['type']
            
            # Get appropriate mask
            mask = self.redaction_masks.get(pii_type, self.redaction_masks['default'])
            
            # Replace the detected PII with the mask
            result_text = result_text[:start] + mask + result_text[end:]
        
        return result_text
    
    def sanitize_output(self, text: str) -> str:
        """
        Basic output sanitization to remove potentially harmful content.
        
        Args:
            text: Input text to sanitize
            
        Returns:
            Sanitized text
        """
        if not text:
            return text
        
        # Remove potential HTML/script tags
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r'<[^>]+>', '', text)  # Remove HTML tags
        
        # Remove potential JavaScript
        text = re.sub(r'javascript\s*:', '', text, flags=re.IGNORECASE)
        text = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', text, flags=re.IGNORECASE)
        
        # Remove data URLs that could contain scripts
        text = re.sub(r'data\s*:\s*text/html[^;]*;[^,]*,.*', '[DATA_URL_REMOVED]', text, flags=re.IGNORECASE)
        
        # Remove potential SQL injection patterns
        text = re.sub(r'(?i)\b(?:union\s+(?:all\s+)?select|select\s+.*\s+from|drop\s+table|delete\s+from)\b', '[SQL_PATTERN_REMOVED]', text)
        
        return text
    
    def filter_content(self, text: str, sanitize: bool = True) -> FilterResult:
        """
        Complete content filtering including PII detection, redaction, and sanitization.
        
        Args:
            text: Input text to filter
            sanitize: Whether to apply output sanitization
            
        Returns:
            FilterResult with processed text and detection details
        """
        if not text:
            return FilterResult(
                filtered_text='',
                detections=[],
                pii_found=False,
                original_text=text,
                redaction_count=0
            )
        
        original_text = text
        
        # Detect PII
        detections = self.detect_pii(text)
        pii_found = len(detections) > 0
        
        # Redact PII
        filtered_text = self.redact_text(text, detections)
        redaction_count = len(detections)
        
        # Apply sanitization if requested
        if sanitize:
            filtered_text = self.sanitize_output(filtered_text)
        
        return FilterResult(
            filtered_text=filtered_text,
            detections=detections,
            pii_found=pii_found,
            original_text=original_text,
            redaction_count=redaction_count
        )
    
    def has_pii(self, text: str) -> bool:
        """Quick check if text contains PII."""
        detections = self.detect_pii(text)
        return len(detections) > 0
    
    def get_pii_types_found(self, text: str) -> Set[str]:
        """Get set of PII types found in text."""
        detections = self.detect_pii(text)
        return {detection['type'] for detection in detections}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current filter statistics and configuration."""
        return {
            'enabled_detections': list(self.enabled_detections),
            'custom_patterns': len(self.custom_patterns),
            'redaction_enabled': self.redaction_enabled,
            'available_masks': list(self.redaction_masks.keys()),
            'builtin_pattern_count': len(self.pattern_matcher.pii_patterns)
        }