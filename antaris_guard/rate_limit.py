"""
RateLimiter - Token bucket rate limiting with file-based persistence.
"""
import json
import logging
import os
import time
import threading
from typing import Dict, Optional, Any
from dataclasses import dataclass
from .utils import atomic_write_json

logger = logging.getLogger(__name__)


@dataclass
class BucketState:
    """Token bucket state."""
    tokens: float
    last_update: float
    requests_made: int
    first_request: float


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    remaining_tokens: float
    reset_time: float
    retry_after: Optional[float]
    requests_made: int


class RateLimiter:
    """
    Token bucket rate limiter with file-based persistence.
    
    Features:
    - Per-source rate limits
    - Configurable burst allowance
    - File-based state persistence
    - Single-process thread-safe operations (not multi-process safe)
    - Automatic cleanup of old buckets
    """
    
    def __init__(self, state_file: str = "./rate_limit_state.json",
                 default_requests_per_second: float = 10.0,
                 default_burst_size: int = 20,
                 cleanup_interval: int = 300):  # 5 minutes
        """
        Initialize RateLimiter.
        
        Args:
            state_file: Path to state persistence file
            default_requests_per_second: Default RPS limit
            default_burst_size: Default burst allowance
            cleanup_interval: Seconds between cleanup operations
        """
        self.state_file = state_file
        self.default_rps = default_requests_per_second
        self.default_burst = default_burst_size
        self.cleanup_interval = cleanup_interval
        
        # Per-source bucket configurations
        self.source_configs: Dict[str, Dict[str, Any]] = {}
        
        # Current bucket states
        self.buckets: Dict[str, BucketState] = {}
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Last cleanup time
        self.last_cleanup = time.time()
        
        # Load persisted state
        self._load_state()
    
    def _load_state(self) -> None:
        """Load rate limiter state from file."""
        if not os.path.exists(self.state_file):
            return
        
        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)
            
            # Load source configurations
            self.source_configs = data.get('source_configs', {})
            
            # Load bucket states
            bucket_data = data.get('buckets', {})
            for source_id, bucket_info in bucket_data.items():
                self.buckets[source_id] = BucketState(
                    tokens=bucket_info['tokens'],
                    last_update=bucket_info['last_update'],
                    requests_made=bucket_info['requests_made'],
                    first_request=bucket_info['first_request']
                )
                
        except (json.JSONDecodeError, KeyError, TypeError):
            # Start with empty state if loading fails
            pass
    
    def _save_state(self) -> None:
        """Save current state to file."""
        data = {
            'source_configs': self.source_configs,
            'buckets': {}
        }
        
        for source_id, bucket in self.buckets.items():
            data['buckets'][source_id] = {
                'tokens': bucket.tokens,
                'last_update': bucket.last_update,
                'requests_made': bucket.requests_made,
                'first_request': bucket.first_request
            }
        
        try:
            atomic_write_json(self.state_file, data)
        except OSError:
            # atomic_write_json already logged the error
            pass
    
    def set_source_config(self, source_id: str, requests_per_second: float, 
                         burst_size: int) -> None:
        """
        Set rate limit configuration for a specific source.
        
        Args:
            source_id: Source identifier
            requests_per_second: Requests per second limit
            burst_size: Burst allowance (tokens in bucket)
        """
        with self.lock:
            self.source_configs[source_id] = {
                'rps': requests_per_second,
                'burst': burst_size
            }
            self._save_state()
    
    def remove_source_config(self, source_id: str) -> None:
        """Remove rate limit configuration for a source (falls back to defaults)."""
        with self.lock:
            self.source_configs.pop(source_id, None)
            self.buckets.pop(source_id, None)
            self._save_state()
    
    def _get_source_config(self, source_id: str) -> tuple:
        """Get rate limit configuration for a source."""
        config = self.source_configs.get(source_id, {})
        rps = config.get('rps', self.default_rps)
        burst = config.get('burst', self.default_burst)
        return rps, burst
    
    def _update_bucket(self, source_id: str) -> BucketState:
        """Update token bucket state for a source."""
        current_time = time.time()
        rps, burst_size = self._get_source_config(source_id)
        
        if source_id not in self.buckets:
            # Initialize new bucket
            bucket = BucketState(
                tokens=float(burst_size),
                last_update=current_time,
                requests_made=0,
                first_request=current_time
            )
            self.buckets[source_id] = bucket
        else:
            bucket = self.buckets[source_id]
            
            # Add tokens based on elapsed time
            elapsed = current_time - bucket.last_update
            tokens_to_add = elapsed * rps
            bucket.tokens = min(burst_size, bucket.tokens + tokens_to_add)
            bucket.last_update = current_time
        
        return bucket
    
    def check_rate_limit(self, source_id: str, tokens_requested: float = 1.0) -> RateLimitResult:
        """
        Check if request should be allowed under rate limit.
        
        Args:
            source_id: Source identifier
            tokens_requested: Number of tokens requested (default 1.0)
            
        Returns:
            RateLimitResult with decision and metadata
        """
        with self.lock:
            # Cleanup old buckets if needed
            self._cleanup_if_needed()
            
            # Update bucket state
            bucket = self._update_bucket(source_id)
            rps, burst_size = self._get_source_config(source_id)
            
            # Check if request can be fulfilled
            allowed = bucket.tokens >= tokens_requested
            
            if allowed:
                # Consume tokens
                bucket.tokens -= tokens_requested
                bucket.requests_made += 1
            
            # Calculate when bucket will be full again
            tokens_needed = burst_size - bucket.tokens
            reset_time = time.time() + (tokens_needed / rps)
            
            # Calculate retry after if request was denied
            retry_after = None
            if not allowed:
                tokens_needed_for_request = tokens_requested - bucket.tokens
                retry_after = max(0, tokens_needed_for_request / rps)
            
            # Save state after changes
            if allowed:
                self._save_state()
            
            return RateLimitResult(
                allowed=allowed,
                remaining_tokens=bucket.tokens,
                reset_time=reset_time,
                retry_after=retry_after,
                requests_made=bucket.requests_made
            )
    
    def consume_tokens(self, source_id: str, tokens: float = 1.0) -> bool:
        """
        Attempt to consume tokens from rate limiter.
        
        Args:
            source_id: Source identifier  
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False if rate limited
        """
        result = self.check_rate_limit(source_id, tokens)
        return result.allowed
    
    def get_bucket_status(self, source_id: str) -> Dict[str, Any]:
        """
        Get current status of a source's token bucket.
        
        Args:
            source_id: Source identifier
            
        Returns:
            Dictionary with bucket status information
        """
        with self.lock:
            bucket = self._update_bucket(source_id)
            rps, burst_size = self._get_source_config(source_id)
            
            current_time = time.time()
            tokens_needed = burst_size - bucket.tokens
            reset_time = current_time + (tokens_needed / rps)
            
            return {
                'source_id': source_id,
                'tokens': bucket.tokens,
                'burst_size': burst_size,
                'requests_per_second': rps,
                'requests_made': bucket.requests_made,
                'first_request': bucket.first_request,
                'last_update': bucket.last_update,
                'reset_time': reset_time,
                'time_to_reset': max(0, reset_time - current_time)
            }
    
    def reset_bucket(self, source_id: str) -> None:
        """Reset token bucket for a source to full capacity."""
        with self.lock:
            rps, burst_size = self._get_source_config(source_id)
            current_time = time.time()
            
            self.buckets[source_id] = BucketState(
                tokens=float(burst_size),
                last_update=current_time,
                requests_made=0,
                first_request=current_time
            )
            self._save_state()
    
    def _cleanup_if_needed(self) -> None:
        """Clean up old bucket states if cleanup interval has elapsed."""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        # Remove buckets that haven't been used in 24 hours
        cutoff_time = current_time - (24 * 3600)
        sources_to_remove = []
        
        for source_id, bucket in self.buckets.items():
            if bucket.last_update < cutoff_time:
                sources_to_remove.append(source_id)
        
        for source_id in sources_to_remove:
            del self.buckets[source_id]
        
        self.last_cleanup = current_time
        
        # Save state if any buckets were removed
        if sources_to_remove:
            self._save_state()
    
    def cleanup_old_buckets(self, max_age_hours: int = 24) -> int:
        """
        Manually clean up old bucket states.
        
        Args:
            max_age_hours: Maximum age of buckets to keep
            
        Returns:
            Number of buckets removed
        """
        with self.lock:
            cutoff_time = time.time() - (max_age_hours * 3600)
            sources_to_remove = []
            
            for source_id, bucket in self.buckets.items():
                if bucket.last_update < cutoff_time:
                    sources_to_remove.append(source_id)
            
            for source_id in sources_to_remove:
                del self.buckets[source_id]
            
            if sources_to_remove:
                self._save_state()
            
            return len(sources_to_remove)
    
    def get_all_sources(self) -> Dict[str, Dict[str, Any]]:
        """Get status for all sources with active buckets."""
        with self.lock:
            result = {}
            for source_id in self.buckets.keys():
                result[source_id] = self.get_bucket_status(source_id)
            return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        with self.lock:
            total_requests = sum(bucket.requests_made for bucket in self.buckets.values())
            active_sources = len(self.buckets)
            configured_sources = len(self.source_configs)
            
            return {
                'active_sources': active_sources,
                'configured_sources': configured_sources,
                'total_requests_tracked': total_requests,
                'state_file': self.state_file,
                'default_rps': self.default_rps,
                'default_burst': self.default_burst,
                'cleanup_interval': self.cleanup_interval,
                'last_cleanup': self.last_cleanup
            }