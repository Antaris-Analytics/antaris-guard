"""
Per-conversation state management for stateful guard policies.

Tracks message history, threat scores, timestamps, and cost accumulation
on a per-conversation_id basis. State is in-memory only (not persisted).

Zero dependencies, pure Python, thread-safe.
"""
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MessageRecord:
    """Single message entry in conversation history."""
    timestamp: float
    text: str
    threat_level: str        # "safe" | "suspicious" | "blocked"
    score: float             # 0.0–1.0
    is_boundary_test: bool   # triggered by repeated boundary probing logic
    cost: float              # USD cost charged for this message


@dataclass
class ConversationState:
    """
    Per-conversation mutable state used by stateful policies.

    Attributes
    ----------
    conversation_id:
        Unique identifier for this conversation.
    created_at:
        Unix timestamp when the state was first created.
    last_seen:
        Unix timestamp of the most recent message.
    messages:
        Ordered list of :class:`MessageRecord` entries (oldest first).
    total_cost:
        Cumulative cost charged across all messages in this conversation.
    """
    conversation_id: str
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    messages: List[MessageRecord] = field(default_factory=list)
    total_cost: float = 0.0


class ConversationStateStore:
    """
    Thread-safe in-memory store of :class:`ConversationState` objects.

    State is keyed by *conversation_id* and automatically evicted when
    the conversation is idle for longer than *ttl_seconds*.

    Parameters
    ----------
    ttl_seconds:
        Time-to-live for idle conversations (default: 3600 s = 1 hour).
        Pass ``None`` to disable TTL eviction entirely.
    max_messages_per_conv:
        Cap on stored messages per conversation to bound memory usage.
        Oldest messages are dropped first when the cap is exceeded.
    """

    DEFAULT_TTL: int = 3600  # 1 hour

    def __init__(
        self,
        ttl_seconds: Optional[int] = DEFAULT_TTL,
        max_messages_per_conv: int = 500,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_messages_per_conv = max_messages_per_conv
        self._store: Dict[str, ConversationState] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_or_create(self, conversation_id: str) -> ConversationState:
        """Return existing state or create a fresh one for *conversation_id*."""
        self._evict_stale()
        with self._lock:
            if conversation_id not in self._store:
                self._store[conversation_id] = ConversationState(
                    conversation_id=conversation_id
                )
            return self._store[conversation_id]

    def get(self, conversation_id: str) -> Optional[ConversationState]:
        """Return state for *conversation_id* or ``None`` if not present."""
        with self._lock:
            return self._store.get(conversation_id)

    def record_message(
        self,
        conversation_id: str,
        text: str,
        threat_level: str,
        score: float,
        cost: float = 0.0,
    ) -> ConversationState:
        """
        Append a message to the conversation history and return the updated state.

        Parameters
        ----------
        conversation_id:
            Conversation to update.
        text:
            Raw message text.
        threat_level:
            ``"safe"``, ``"suspicious"``, or ``"blocked"``.
        score:
            Float threat score 0.0–1.0.
        cost:
            USD cost to charge for this message.
        """
        self._evict_stale()
        with self._lock:
            state = self._store.setdefault(
                conversation_id,
                ConversationState(conversation_id=conversation_id),
            )
            now = time.time()
            state.last_seen = now
            state.total_cost += cost

            # Detect boundary testing: suspicious/blocked message after ≥ 1
            # previous suspicious/blocked message in recent window
            recent = state.messages[-10:]
            prior_threats = sum(
                1 for m in recent
                if m.threat_level in ("suspicious", "blocked")
            )
            is_boundary_test = (
                threat_level in ("suspicious", "blocked") and prior_threats >= 1
            )

            record = MessageRecord(
                timestamp=now,
                text=text,
                threat_level=threat_level,
                score=score,
                is_boundary_test=is_boundary_test,
                cost=cost,
            )
            state.messages.append(record)

            # Trim to cap
            if len(state.messages) > self.max_messages_per_conv:
                state.messages = state.messages[-self.max_messages_per_conv:]

            return state

    def end_conversation(self, conversation_id: str) -> bool:
        """
        Remove state for *conversation_id*.

        Returns ``True`` if the conversation existed and was removed.
        """
        with self._lock:
            if conversation_id in self._store:
                del self._store[conversation_id]
                return True
            return False

    def active_conversations(self) -> List[str]:
        """Return a sorted list of currently tracked conversation IDs."""
        with self._lock:
            return sorted(self._store.keys())

    def snapshot(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        """
        Return a plain-dict snapshot of *conversation_id* state.

        Useful for serialization and debugging. Returns ``None`` if the
        conversation is not tracked.
        """
        with self._lock:
            state = self._store.get(conversation_id)
            if state is None:
                return None
            return {
                "conversation_id": state.conversation_id,
                "created_at": state.created_at,
                "last_seen": state.last_seen,
                "message_count": len(state.messages),
                "total_cost": state.total_cost,
                "threat_summary": {
                    "safe": sum(1 for m in state.messages if m.threat_level == "safe"),
                    "suspicious": sum(1 for m in state.messages if m.threat_level == "suspicious"),
                    "blocked": sum(1 for m in state.messages if m.threat_level == "blocked"),
                },
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_stale(self) -> None:
        """Remove conversations that have been idle beyond *ttl_seconds*."""
        if self.ttl_seconds is None:
            return
        cutoff = time.time() - self.ttl_seconds
        with self._lock:
            stale = [
                cid for cid, state in self._store.items()
                if state.last_seen < cutoff
            ]
            for cid in stale:
                del self._store[cid]
