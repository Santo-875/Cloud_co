"""Tests for app/store.py."""

import time

from app.models import Architecture, Node
from app.store import InMemoryStore


def _sample_arch(name: str = "test") -> Architecture:
    return Architecture(
        name=name,
        region="us-east-1",
        nodes=[Node(id="v1", type="vpc", props={"cidr": "10.0.0.0/16"})],
    )


def test_store_save_and_get() -> None:
    store = InMemoryStore(max_entries=10, ttl_seconds=60)
    arch = _sample_arch("first")
    arch_id = store.save(arch)

    retrieved = store.get(arch_id)
    assert retrieved is not None
    assert retrieved.name == "first"
    assert store.size() == 1


def test_store_lru_capacity_eviction() -> None:
    store = InMemoryStore(max_entries=2, ttl_seconds=60)
    id1 = store.save(_sample_arch("one"))
    id2 = store.save(_sample_arch("two"))

    # Access id1 to make it most recently used
    _ = store.get(id1)

    # Insert third, should evict id2
    id3 = store.save(_sample_arch("three"))

    assert store.get(id1) is not None
    assert store.get(id2) is None  # evicted
    assert store.get(id3) is not None
    assert store.size() == 2


def test_store_ttl_expiration() -> None:
    store = InMemoryStore(max_entries=10, ttl_seconds=0.1)
    arch_id = store.save(_sample_arch("short_lived"))

    assert store.get(arch_id) is not None
    time.sleep(0.15)
    assert store.get(arch_id) is None
    assert store.size() == 0


def test_store_delete_and_clear() -> None:
    store = InMemoryStore()
    arch_id = store.save(_sample_arch("del_test"))
    assert store.delete(arch_id) is True
    assert store.get(arch_id) is None

    store.save(_sample_arch("c1"))
    store.save(_sample_arch("c2"))
    assert store.size() == 2
    store.clear()
    assert store.size() == 0
