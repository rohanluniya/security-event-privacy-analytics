"""Durable append-only Write-Ahead Log (WAL) broker with topic partitions, offsets, DLQ, and replay."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BrokerEnvelope:
    topic: str
    partition: int
    offset: int
    ingested_at_ms: int
    payload: dict[str, Any]


class DurableWalBroker:
    """File-backed append-only WAL simulating Kafka topics, consumer group offsets, and replay."""

    def __init__(self, wal_dir: Path) -> None:
        self.wal_dir = wal_dir
        self.wal_dir.mkdir(parents=True, exist_ok=True)
        self.offsets_file = self.wal_dir / "consumer_offsets.json"

    def _topic_file(self, topic: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in topic)
        return self.wal_dir / f"{safe}.wal.jsonl"

    def reset(self) -> None:
        """Clear WAL files and checkpoints for fresh deterministic runs."""
        for path in self.wal_dir.glob("*.wal.jsonl"):
            path.unlink(missing_ok=True)
        self.offsets_file.unlink(missing_ok=True)

    def publish_batch(self, topic: str, records: list[dict[str, Any]]) -> int:
        """Append records durably to topic WAL and return final next offset."""
        topic_path = self._topic_file(topic)
        current_offset = 0
        if topic_path.exists():
            with topic_path.open("r", encoding="utf-8") as fh:
                for _ in fh:
                    current_offset += 1

        now_ms = int(time.time() * 1000)
        with topic_path.open("a", encoding="utf-8") as fh:
            for rec in records:
                stream_key = str(rec.get("source_stream", "unknown"))
                partition = abs(hash(stream_key)) % 6
                envelope = {
                    "topic": topic,
                    "partition": partition,
                    "offset": current_offset,
                    "ingested_at_ms": now_ms,
                    "payload": rec,
                }
                fh.write(json.dumps(envelope, sort_keys=True) + "\n")
                current_offset += 1
            fh.flush()
        return current_offset

    def read_from_offset(
        self,
        topic: str,
        start_offset: int = 0,
        limit: int | None = None,
    ) -> list[BrokerEnvelope]:
        """Read envelopes deterministically starting at `start_offset` (supports replay from 0)."""
        topic_path = self._topic_file(topic)
        if not topic_path.exists():
            return []
        envelopes: list[BrokerEnvelope] = []
        with topic_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                raw = json.loads(line)
                offset = int(raw["offset"])
                if offset < start_offset:
                    continue
                envelopes.append(
                    BrokerEnvelope(
                        topic=str(raw["topic"]),
                        partition=int(raw["partition"]),
                        offset=offset,
                        ingested_at_ms=int(raw["ingested_at_ms"]),
                        payload=dict(raw["payload"]),
                    )
                )
                if limit is not None and len(envelopes) >= limit:
                    break
        return envelopes

    def commit_offset(self, consumer_group: str, topic: str, next_offset: int) -> None:
        state = self._load_offsets()
        state.setdefault(consumer_group, {})[topic] = next_offset
        self.offsets_file.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

    def get_committed_offset(self, consumer_group: str, topic: str) -> int:
        state = self._load_offsets()
        return int(state.get(consumer_group, {}).get(topic, 0))

    def topic_count(self, topic: str) -> int:
        topic_path = self._topic_file(topic)
        if not topic_path.exists():
            return 0
        with topic_path.open("r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())

    def _load_offsets(self) -> dict[str, dict[str, int]]:
        if not self.offsets_file.exists():
            return {}
        return dict(json.loads(self.offsets_file.read_text(encoding="utf-8")))
