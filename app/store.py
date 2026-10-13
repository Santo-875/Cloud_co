"""Thread-safe in-memory architecture store with LRU eviction and TTL."""

import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass

from app.models import Architecture, ArchitecturePatch


@dataclass
class StoreEntry:
    architecture: Architecture
    created_at: float


class InMemoryStore:
    """In-memory thread-safe architecture store with TTL and capacity limits."""

    def __init__(self, max_entries: int = 100, ttl_seconds: int = 3600) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._entries: OrderedDict[str, StoreEntry] = OrderedDict()
        self._lock = threading.Lock()

    def _purge_expired_locked(self, now: float) -> None:
        expired_keys = [
            k
            for k, entry in self._entries.items()
            if now - entry.created_at > self.ttl_seconds
        ]
        for k in expired_keys:
            del self._entries[k]

    def save(self, architecture: Architecture) -> str:
        """Store architecture and return a random UUID string."""
        arch_id = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            self._purge_expired_locked(now)
            # Evict oldest entry if at capacity
            while len(self._entries) >= self.max_entries:
                self._entries.popitem(last=False)
            self._entries[arch_id] = StoreEntry(
                architecture=architecture, created_at=now
            )
        return arch_id

    def get(self, arch_id: str) -> Architecture | None:
        """Retrieve stored architecture by ID if present and not expired."""
        now = time.time()
        with self._lock:
            entry = self._entries.get(arch_id)
            if not entry:
                return None
            if now - entry.created_at > self.ttl_seconds:
                del self._entries[arch_id]
                return None
            # Move to end (most recently used)
            self._entries.move_to_end(arch_id)
            return entry.architecture

    def update(self, arch_id: str, architecture: Architecture) -> bool:
        """Update existing stored architecture in place."""
        now = time.time()
        with self._lock:
            if arch_id not in self._entries:
                return False
            self._entries[arch_id] = StoreEntry(
                architecture=architecture, created_at=now
            )
            self._entries.move_to_end(arch_id)
            return True

    def delete(self, arch_id: str) -> bool:
        """Delete entry by ID."""
        with self._lock:
            return self._entries.pop(arch_id, None) is not None

    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        """Return count of active valid entries."""
        now = time.time()
        with self._lock:
            self._purge_expired_locked(now)
            return len(self._entries)


@dataclass
class PatchStoreEntry:
    patch: "ArchitecturePatch"
    created_at: float


class InMemoryPatchStore:
    """Thread-safe store for generated patches."""

    def __init__(self, max_entries: int = 100, ttl_seconds: int = 3600) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._entries: OrderedDict[str, PatchStoreEntry] = OrderedDict()
        self._lock = threading.Lock()

    def save(self, patch: "ArchitecturePatch") -> str:
        """Store patch and return patch_id."""
        now = time.time()
        with self._lock:
            while len(self._entries) >= self.max_entries:
                self._entries.popitem(last=False)
            self._entries[patch.patch_id] = PatchStoreEntry(patch=patch, created_at=now)
        return patch.patch_id

    def get(self, patch_id: str) -> "ArchitecturePatch | None":
        """Retrieve stored patch if valid and unexpired."""
        now = time.time()
        with self._lock:
            entry = self._entries.get(patch_id)
            if not entry:
                return None
            if now - entry.created_at > self.ttl_seconds:
                del self._entries[patch_id]
                return None
            self._entries.move_to_end(patch_id)
            return entry.patch

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# Default global store instances
GLOBAL_STORE = InMemoryStore()
GLOBAL_PATCH_STORE = InMemoryPatchStore()
