import asyncio
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
from store.schema import APIEntry


def _endpoint_key(endpoint: str, method: str) -> str:
    return hashlib.md5(f"{method.upper()}::{endpoint.lower()}".encode()).hexdigest()


class APIStore:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._entries: Dict[str, APIEntry] = {}

    async def upsert(
        self,
        endpoint: str,
        method: str = "UNKNOWN",
        source: str = "unknown",
        **kwargs,
    ) -> APIEntry:
        key = _endpoint_key(endpoint, method)
        async with self._lock:
            if key in self._entries:
                entry = self._entries[key]
                if source not in entry.discovered_by:
                    entry.discovered_by.append(source)
                entry.last_seen = datetime.utcnow().isoformat() + "Z"
                for k, v in kwargs.items():
                    if v is not None and hasattr(entry, k):
                        existing = getattr(entry, k)
                        if isinstance(existing, list) and isinstance(v, list):
                            for item in v:
                                if item not in existing:
                                    existing.append(item)
                        elif isinstance(existing, dict) and isinstance(v, dict):
                            existing.update(v)
                        elif existing in (None, "UNKNOWN", "unknown", "LOW", 0, ""):
                            setattr(entry, k, v)
            else:
                entry = APIEntry(
                    endpoint=endpoint,
                    method=method,
                    discovered_by=[source],
                    **{k: v for k, v in kwargs.items() if v is not None and hasattr(APIEntry, k)},
                )
                self._entries[key] = entry
        return entry

    def sync_upsert(self, endpoint: str, method: str = "UNKNOWN", source: str = "unknown", **kwargs) -> APIEntry:
        key = _endpoint_key(endpoint, method)
        if key in self._entries:
            entry = self._entries[key]
            if source not in entry.discovered_by:
                entry.discovered_by.append(source)
            entry.last_seen = datetime.utcnow().isoformat() + "Z"
            for k, v in kwargs.items():
                if v is not None and hasattr(entry, k):
                    existing = getattr(entry, k)
                    if isinstance(existing, list) and isinstance(v, list):
                        for item in v:
                            if item not in existing:
                                existing.append(item)
                    elif existing in (None, "UNKNOWN", "unknown", "LOW", 0, ""):
                        setattr(entry, k, v)
        else:
            entry = APIEntry(
                endpoint=endpoint,
                method=method,
                discovered_by=[source],
                **{k: v for k, v in kwargs.items() if hasattr(APIEntry, k)},
            )
            self._entries[key] = entry
        return entry

    def all(self) -> List[APIEntry]:
        return list(self._entries.values())

    def by_classification(self, classification: str) -> List[APIEntry]:
        return [e for e in self._entries.values() if e.classification == classification]

    def count(self) -> Dict[str, int]:
        counts = {"total": len(self._entries), "Valid": 0, "Shadow": 0, "New": 0, "Rogue": 0, "UNCLASSIFIED": 0}
        for e in self._entries.values():
            c = e.classification
            counts[c] = counts.get(c, 0) + 1
        return counts

    def seen_endpoint(self, endpoint: str) -> bool:
        for method in ["GET", "POST", "UNKNOWN"]:
            key = _endpoint_key(endpoint, method)
            if key in self._entries:
                return True
        return False
