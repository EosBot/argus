"""Evidence chain preservation — SHA-256 hash chain for findings.

Provides an append-only, immutable log where each entry references
the SHA-256 hash of the previous entry, forming a cryptographic chain.
Any alteration to an earlier entry invalidates all subsequent entries.

This is a lightweight variant of the full chain-of-custody module
(:mod:`argus.evidence.chain_of_custody`) focused on finding correlation
events rather than raw evidence capture.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Genesis hash — the first entry points to this fixed value.
_GENESIS_HASH: str = "0" * 64


@dataclass(frozen=True, slots=True)
class ChainEntry:
    """An immutable entry in the evidence chain.

    Attributes:
        entry_id: Unique identifier (UUID hex).
        investigation_id: Associated investigation.
        event_type: Type of event (finding_created, correlation_found, ...).
        data: Event payload (JSON-serializable).
        data_hash: SHA-256 of the serialized data.
        previous_hash: SHA-256 of the previous entry (hash chain linkage).
        entry_hash: SHA-256 of this entry (excludes entry_hash itself).
        timestamp: ISO 8601 creation timestamp (UTC).
        sequence: Monotonically increasing sequence number.
    """

    entry_id: str
    investigation_id: str
    event_type: str
    data: dict[str, Any]
    data_hash: str
    previous_hash: str
    entry_hash: str
    timestamp: str
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "investigation_id": self.investigation_id,
            "event_type": self.event_type,
            "data": self.data,
            "data_hash": self.data_hash,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
            "timestamp": self.timestamp,
            "sequence": self.sequence,
        }


class EvidenceChain:
    """Append-only SHA-256 hash chain for evidence preservation.

    Each entry links to the previous one via ``previous_hash``, forming
    an immutable chain. The chain is stored in memory but can be
    serialized to JSON for persistence.

    Usage::

        chain = EvidenceChain(investigation_id="inv-001")
        entry = await chain.append("finding_created", {"finding_id": "abc"})
        ok = await chain.verify_integrity()
    """

    def __init__(self, investigation_id: str = "") -> None:
        self._entries: list[ChainEntry] = []
        self._investigation_id = investigation_id

    @property
    def investigation_id(self) -> str:
        return self._investigation_id

    @property
    def length(self) -> int:
        return len(self._entries)

    async def append(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        investigation_id: str = "",
    ) -> ChainEntry:
        """Append a new entry to the chain.

        Computes the SHA-256 hash of the data, links to the previous
        entry's hash, and computes the entry's own hash.

        Args:
            event_type: Type of event being recorded.
            data: Event payload (must be JSON-serializable).
            investigation_id: Override the chain's default investigation ID.

        Returns:
            The newly created ChainEntry.
        """
        inv_id = investigation_id or self._investigation_id
        if not inv_id:
            raise ValueError("investigation_id must be provided")

        previous = self._entries[-1] if self._entries else None
        previous_hash = previous.entry_hash if previous is not None else _GENESIS_HASH

        data_hash = _sha256(_serialize(data))
        sequence = len(self._entries)

        entry = ChainEntry(
            entry_id=uuid.uuid4().hex,
            investigation_id=inv_id,
            event_type=event_type,
            data=data,
            data_hash=data_hash,
            previous_hash=previous_hash,
            entry_hash="",  # Computed below
            timestamp=datetime.now(timezone.utc).isoformat(),
            sequence=sequence,
        )

        entry_hash = _sha256(_canonical(entry))
        # Replace with computed hash (dataclass is frozen, so recreate)
        signed = ChainEntry(
            entry_id=entry.entry_id,
            investigation_id=entry.investigation_id,
            event_type=entry.event_type,
            data=entry.data,
            data_hash=entry.data_hash,
            previous_hash=entry.previous_hash,
            entry_hash=entry_hash,
            timestamp=entry.timestamp,
            sequence=entry.sequence,
        )

        self._entries.append(signed)
        return signed

    async def get_entry(self, entry_id: str) -> ChainEntry | None:
        """Retrieve an entry by ID."""
        for entry in self._entries:
            if entry.entry_id == entry_id:
                return entry
        return None

    async def get_entry_by_sequence(self, sequence: int) -> ChainEntry | None:
        """Retrieve an entry by sequence number."""
        if 0 <= sequence < len(self._entries):
            return self._entries[sequence]
        return None

    async def get_all(self) -> list[ChainEntry]:
        """Return all entries in insertion order."""
        return list(self._entries)

    async def get_last(self) -> ChainEntry | None:
        """Return the last entry, or None if chain is empty."""
        if not self._entries:
            return None
        return self._entries[-1]

    async def verify_integrity(self) -> bool:
        """Verify the integrity of the entire chain.

        Checks:
        1. Each entry's ``previous_hash`` matches the previous entry's ``entry_hash``.
        2. Each entry's ``data_hash`` matches its data.
        3. Each entry's ``entry_hash`` matches its canonical form.

        Returns:
            True if the chain is intact.

        Raises:
            EvidenceChainError: If any check fails.
        """
        expected_previous = _GENESIS_HASH

        for entry in self._entries:
            # Check linkage
            if entry.previous_hash != expected_previous:
                raise EvidenceChainError(
                    f"Chain broken at sequence {entry.sequence}: "
                    f"previous_hash mismatch "
                    f"(expected {expected_previous[:16]}..., "
                    f"got {entry.previous_hash[:16]}...)"
                )

            # Check data integrity
            if _sha256(_serialize(entry.data)) != entry.data_hash:
                raise EvidenceChainError(
                    f"Data corrupted at sequence {entry.sequence}: "
                    f"data_hash mismatch"
                )

            # Check entry integrity
            if _sha256(_canonical(entry)) != entry.entry_hash:
                raise EvidenceChainError(
                    f"Entry corrupted at sequence {entry.sequence}: "
                    f"entry_hash mismatch"
                )

            expected_previous = entry.entry_hash

        return True

    async def verify_entry(self, entry_id: str) -> bool:
        """Verify a specific entry and the chain up to it.

        Args:
            entry_id: The entry to verify.

        Returns:
            True if the entry and chain up to it are intact.

        Raises:
            EvidenceChainError: If verification fails.
            EntryNotFoundError: If the entry doesn't exist.
        """
        target_sequence: int | None = None
        for entry in self._entries:
            if entry.entry_id == entry_id:
                target_sequence = entry.sequence
                break

        if target_sequence is None:
            raise EntryNotFoundError(entry_id)

        expected_previous = _GENESIS_HASH
        for entry in self._entries:
            if entry.sequence > target_sequence:
                break

            if entry.previous_hash != expected_previous:
                raise EvidenceChainError(
                    f"Chain broken at sequence {entry.sequence}"
                )
            if _sha256(_serialize(entry.data)) != entry.data_hash:
                raise EvidenceChainError(
                    f"Data corrupted at sequence {entry.sequence}"
                )
            if _sha256(_canonical(entry)) != entry.entry_hash:
                raise EvidenceChainError(
                    f"Entry corrupted at sequence {entry.sequence}"
                )

            expected_previous = entry.entry_hash

        return True

    def to_json(self) -> str:
        """Serialize the entire chain to JSON."""
        return json.dumps(
            [entry.to_dict() for entry in self._entries],
            indent=2,
            default=str,
        )

    @classmethod
    def from_json(cls, json_str: str) -> EvidenceChain:
        """Deserialize a chain from JSON.

        Note: this reconstructs the chain but does NOT verify integrity.
        Call :meth:`verify_integrity` after loading.
        """
        raw = json.loads(json_str)
        chain = cls()
        for raw_entry in raw:
            entry = ChainEntry(
                entry_id=raw_entry["entry_id"],
                investigation_id=raw_entry["investigation_id"],
                event_type=raw_entry["event_type"],
                data=raw_entry["data"],
                data_hash=raw_entry["data_hash"],
                previous_hash=raw_entry["previous_hash"],
                entry_hash=raw_entry["entry_hash"],
                timestamp=raw_entry["timestamp"],
                sequence=raw_entry["sequence"],
            )
            chain._entries.append(entry)
        return chain


class EvidenceChainError(Exception):
    """Raised when evidence chain integrity is violated."""


class EntryNotFoundError(KeyError):
    """Raised when an entry ID is not found in the chain."""


def _sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def _serialize(value: Any) -> bytes:
    """Serialize a value to canonical JSON bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _canonical(entry: ChainEntry) -> bytes:
    """Serialize an entry to canonical JSON bytes (excludes entry_hash)."""
    fields: dict[str, Any] = {
        "entry_id": entry.entry_id,
        "investigation_id": entry.investigation_id,
        "event_type": entry.event_type,
        "data_hash": entry.data_hash,
        "previous_hash": entry.previous_hash,
        "timestamp": entry.timestamp,
        "sequence": entry.sequence,
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
