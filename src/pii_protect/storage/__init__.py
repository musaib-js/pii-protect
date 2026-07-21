"""
pii_protect.storage
=====================
Pluggable storage backends for the PII vault.

``StorageBackend`` is the abstract contract. ``InMemoryStorage`` and
``FileSystemStorage`` have no optional dependencies and are always
importable. ``RedisStorage`` and ``PostgresStorage`` require their
respective extras (``pii-shield[redis]`` / ``pii-shield[postgres]``);
importing this module never fails even if those extras aren't installed —
the ImportError is only raised if you actually try to construct or
connect() one of those backends.

Author: Musaib Altaf
"""

from pii_protect.storage.base import StorageBackend
from pii_protect.storage.filesystem import FileSystemStorage
from pii_protect.storage.memory import InMemoryStorage
from pii_protect.storage.postgres import PostgresStorage
from pii_protect.storage.redis_backend import RedisStorage

__all__ = [
    "StorageBackend",
    "InMemoryStorage",
    "FileSystemStorage",
    "RedisStorage",
    "PostgresStorage",
]
