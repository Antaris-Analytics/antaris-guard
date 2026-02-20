"""
AuditLogger - Security event logging for compliance and monitoring.
"""
import glob
import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from .patterns import ThreatLevel


@dataclass
class AuditEvent:
    """Security audit event record."""
    timestamp: float
    event_type: str  # 'guard_analysis', 'content_filter', 'rate_limit', 'custom'
    severity: str   # 'low', 'medium', 'high', 'critical'
    source_id: Optional[str]  # Identifier for the source (user, session, etc.)
    action: str     # 'blocked', 'flagged', 'allowed', 'filtered'
    details: Dict[str, Any]
    metadata: Dict[str, Any]


class AuditLogger:
    """
    Security event logging system for compliance and monitoring.
    
    Features:
    - Structured JSON logging
    - Configurable retention policies
    - Event filtering and querying
    - Automatic log rotation
    """
    
    def __init__(self, log_dir: str = "./audit_logs", 
                 retention_days: int = 30,
                 max_log_size_mb: int = 100):
        """
        Initialize AuditLogger.
        
        Args:
            log_dir: Directory to store audit logs
            retention_days: Number of days to retain logs
            max_log_size_mb: Maximum size of a log file in MB
        """
        self.log_dir = log_dir
        self.retention_days = retention_days
        self.max_log_size_bytes = max_log_size_mb * 1024 * 1024
        self.current_log_file = None
        self.enabled = True
        
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Initialize current log file
        self._initialize_log_file()
    
    def _initialize_log_file(self) -> None:
        """Initialize the current log file based on date."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        self.current_log_file = os.path.join(self.log_dir, f"audit_{date_str}.jsonl")
    
    def _get_log_file_for_date(self, date: datetime) -> str:
        """Get log file path for a specific date."""
        date_str = date.strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"audit_{date_str}.jsonl")
    
    def _should_rotate_log(self) -> bool:
        """Check if current log file should be rotated."""
        if not os.path.exists(self.current_log_file):
            return False
            
        # Check file size
        file_size = os.path.getsize(self.current_log_file)
        if file_size >= self.max_log_size_bytes:
            return True
        
        # Check if date has changed
        file_date = datetime.fromtimestamp(os.path.getmtime(self.current_log_file)).date()
        current_date = datetime.now().date()
        return file_date != current_date
    
    def _rotate_log_if_needed(self) -> None:
        """Rotate log file if necessary."""
        if self._should_rotate_log():
            # Archive current file if it's large
            if os.path.exists(self.current_log_file):
                file_size = os.path.getsize(self.current_log_file)
                if file_size >= self.max_log_size_bytes:
                    timestamp = int(time.time())
                    base_name = os.path.splitext(self.current_log_file)[0]
                    archived_name = f"{base_name}_{timestamp}.jsonl"
                    os.rename(self.current_log_file, archived_name)
            
            # Initialize new log file
            self._initialize_log_file()
    
    def enable(self) -> None:
        """Enable audit logging."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable audit logging."""
        self.enabled = False
    
    def log_event(self, event_type: str, severity: str, action: str, 
                  details: Dict[str, Any], source_id: Optional[str] = None,
                  metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a security event.
        
        Args:
            event_type: Type of event ('guard_analysis', 'content_filter', etc.)
            severity: Event severity ('low', 'medium', 'high', 'critical')
            action: Action taken ('blocked', 'flagged', 'allowed', 'filtered')
            details: Event details dictionary
            source_id: Optional source identifier
            metadata: Optional additional metadata
        """
        if not self.enabled:
            return
        
        # Create audit event
        event = AuditEvent(
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            source_id=source_id,
            action=action,
            details=details,
            metadata=metadata or {}
        )
        
        # Rotate log if needed
        self._rotate_log_if_needed()
        
        # Write to log file
        try:
            with open(self.current_log_file, 'a', encoding='utf-8') as f:
                json.dump(asdict(event), f)
                f.write('\n')
                f.flush()
        except (OSError, IOError):
            # Fail silently if logging fails
            pass
    
    def log_guard_analysis(self, threat_level: ThreatLevel, text_sample: str, 
                          matches: List[Dict], source_id: Optional[str] = None,
                          score: float = 0.0) -> None:
        """
        Log a PromptGuard analysis event.
        
        Args:
            threat_level: Detected threat level
            text_sample: Sample of analyzed text (truncated for privacy)
            matches: List of pattern matches
            source_id: Optional source identifier  
            score: Threat score
        """
        # Truncate text sample for privacy
        sample = text_sample[:200] if len(text_sample) > 200 else text_sample
        
        severity_map = {
            ThreatLevel.SAFE: 'low',
            ThreatLevel.SUSPICIOUS: 'medium', 
            ThreatLevel.BLOCKED: 'high'
        }
        
        action_map = {
            ThreatLevel.SAFE: 'allowed',
            ThreatLevel.SUSPICIOUS: 'flagged',
            ThreatLevel.BLOCKED: 'blocked'
        }
        
        self.log_event(
            event_type='guard_analysis',
            severity=severity_map[threat_level],
            action=action_map[threat_level],
            details={
                'threat_level': threat_level.value,
                'text_sample': sample,
                'matches': matches,
                'score': score,
                'match_count': len(matches)
            },
            source_id=source_id
        )
    
    def log_content_filter(self, pii_found: bool, detections: List[Dict], 
                          redaction_count: int, source_id: Optional[str] = None) -> None:
        """
        Log a ContentFilter event.
        
        Args:
            pii_found: Whether PII was detected
            detections: List of PII detections
            redaction_count: Number of redactions made
            source_id: Optional source identifier
        """
        severity = 'medium' if pii_found else 'low'
        action = 'filtered' if redaction_count > 0 else 'allowed'
        
        self.log_event(
            event_type='content_filter',
            severity=severity,
            action=action,
            details={
                'pii_found': pii_found,
                'pii_types': list({d['type'] for d in detections}),
                'detection_count': len(detections),
                'redaction_count': redaction_count
            },
            source_id=source_id
        )
    
    def log_rate_limit(self, source_id: str, limit_exceeded: bool, 
                      current_count: int, limit: int, window_seconds: int) -> None:
        """
        Log a rate limiting event.
        
        Args:
            source_id: Source identifier that hit the limit
            limit_exceeded: Whether the limit was exceeded
            current_count: Current request count
            limit: Rate limit threshold
            window_seconds: Time window for the limit
        """
        severity = 'high' if limit_exceeded else 'low'
        action = 'blocked' if limit_exceeded else 'allowed'
        
        self.log_event(
            event_type='rate_limit',
            severity=severity,
            action=action,
            details={
                'limit_exceeded': limit_exceeded,
                'current_count': current_count,
                'limit': limit,
                'window_seconds': window_seconds
            },
            source_id=source_id
        )
    
    def query_events(self, start_time: Optional[float] = None,
                    end_time: Optional[float] = None,
                    event_type: Optional[str] = None,
                    severity: Optional[str] = None,
                    source_id: Optional[str] = None,
                    limit: int = 100) -> List[AuditEvent]:
        """
        Query audit events with filters.
        
        Args:
            start_time: Start timestamp (Unix time)
            end_time: End timestamp (Unix time)  
            event_type: Filter by event type
            severity: Filter by severity level
            source_id: Filter by source ID
            limit: Maximum number of events to return
            
        Returns:
            List of matching AuditEvent objects
        """
        events = []

        # Determine date range for log files to scan
        if start_time:
            start_date = datetime.fromtimestamp(start_time).date()
        else:
            start_date = (datetime.now() - timedelta(days=7)).date()  # Default last 7 days

        if end_time:
            end_date = datetime.fromtimestamp(end_time).date()
        else:
            end_date = datetime.now().date()

        # Use glob to find ALL audit files (including size-rotated ones like
        # audit_YYYY-MM-DD_<timestamp>.jsonl), then filter by date prefix.
        all_log_files = glob.glob(os.path.join(self.log_dir, "audit_*.jsonl"))

        # Filter to files whose date prefix falls within [start_date, end_date]
        candidate_files = []
        for log_file in sorted(all_log_files):
            basename = os.path.basename(log_file)
            # basename format: audit_YYYY-MM-DD.jsonl  OR  audit_YYYY-MM-DD_<ts>.jsonl
            try:
                # Strip leading "audit_" and trailing ".jsonl", then take first token
                name_part = basename[len("audit_"):-len(".jsonl")]
                date_str = name_part[:10]  # "YYYY-MM-DD"
                file_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            except (ValueError, IndexError):
                continue
            if start_date <= file_date <= end_date:
                candidate_files.append(log_file)

        for log_file in candidate_files:
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            event_data = json.loads(line.strip())
                            event = AuditEvent(**event_data)

                            # Apply filters
                            if start_time and event.timestamp < start_time:
                                continue
                            if end_time and event.timestamp > end_time:
                                continue
                            if event_type and event.event_type != event_type:
                                continue
                            if severity and event.severity != severity:
                                continue
                            if source_id and event.source_id != source_id:
                                continue

                            events.append(event)

                            # Check limit
                            if len(events) >= limit:
                                return events

                        except (json.JSONDecodeError, TypeError):
                            continue

            except (OSError, IOError):
                continue

        return events
    
    def get_event_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get summary of events in the last N hours.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Summary dictionary with event counts and statistics
        """
        end_time = time.time()
        start_time = end_time - (hours * 3600)
        
        events = self.query_events(start_time=start_time, end_time=end_time, limit=10000)
        
        summary = {
            'time_range_hours': hours,
            'total_events': len(events),
            'event_types': {},
            'severities': {},
            'actions': {},
            'top_sources': {}
        }
        
        for event in events:
            # Count by event type
            summary['event_types'][event.event_type] = summary['event_types'].get(event.event_type, 0) + 1
            
            # Count by severity
            summary['severities'][event.severity] = summary['severities'].get(event.severity, 0) + 1
            
            # Count by action
            summary['actions'][event.action] = summary['actions'].get(event.action, 0) + 1
            
            # Count by source
            if event.source_id:
                summary['top_sources'][event.source_id] = summary['top_sources'].get(event.source_id, 0) + 1
        
        return summary
    
    def cleanup_old_logs(self) -> int:
        """
        Remove log files older than retention period.
        
        Returns:
            Number of files removed
        """
        if not os.path.exists(self.log_dir):
            return 0
        
        cutoff_time = time.time() - (self.retention_days * 24 * 3600)
        removed_count = 0
        
        for filename in os.listdir(self.log_dir):
            if filename.startswith('audit_') and filename.endswith('.jsonl'):
                file_path = os.path.join(self.log_dir, filename)
                try:
                    if os.path.getmtime(file_path) < cutoff_time:
                        os.remove(file_path)
                        removed_count += 1
                except (OSError, IOError):
                    continue
        
        return removed_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit logger statistics."""
        log_files = []
        total_size = 0

        if os.path.exists(self.log_dir):
            for filename in os.listdir(self.log_dir):
                if filename.startswith('audit_') and filename.endswith('.jsonl'):
                    file_path = os.path.join(self.log_dir, filename)
                    try:
                        size = os.path.getsize(file_path)
                        total_size += size
                        log_files.append({
                            'filename': filename,
                            'size_bytes': size,
                            'modified': os.path.getmtime(file_path)
                        })
                    except (OSError, IOError):
                        continue

        return {
            'enabled': self.enabled,
            'log_dir': self.log_dir,
            'retention_days': self.retention_days,
            'max_log_size_mb': self.max_log_size_bytes // (1024 * 1024),
            'current_log_file': self.current_log_file,
            'total_log_files': len(log_files),
            'total_size_bytes': total_size,
            'log_files': log_files
        }

    # ------------------------------------------------------------------
    # Sprint 2.5 — Policy decision audit trail
    # ------------------------------------------------------------------

    def log_policy_decision(
        self,
        conversation_id: str,
        policy_name: str,
        decision: str,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
        source_id: Optional[str] = None,
        text_sample: Optional[str] = None,
    ) -> None:
        """
        Log a structured policy decision for compliance audit.

        Every guard decision (allow/deny/modify) that passes through a
        stateful conversation policy is recorded in append-only JSONL format.
        The resulting entries are compliance-ready and suitable for SIEM
        ingestion.

        Parameters
        ----------
        conversation_id:
            Conversation this decision belongs to.
        policy_name:
            Name of the policy that made the decision.
        decision:
            ``"allow"`` or ``"deny"``.
        reason:
            Human-readable explanation from the policy.
        evidence:
            Supporting dict (counts, thresholds, etc.) from
            :attr:`~antaris_guard.policies.StatefulPolicyResult.evidence`.
        source_id:
            Optional source/user identifier.
        text_sample:
            Optional short text snippet (truncated to 200 chars for privacy).
        """
        sample = (text_sample or "")[:200]
        severity = "high" if decision == "deny" else "low"
        action = "blocked" if decision == "deny" else "allowed"

        self.log_event(
            event_type="policy_decision",
            severity=severity,
            action=action,
            details={
                "conversation_id": conversation_id,
                "policy_name": policy_name,
                "decision": decision,
                "reason": reason,
                "evidence": evidence or {},
                "text_sample": sample,
            },
            source_id=source_id,
            metadata={"sprint": "2.5", "audit_type": "stateful_policy"},
        )