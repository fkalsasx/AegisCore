#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AEGIS-VORTEX :: Merkezi Olay Veri Yolu (Asynchronous & Thread-Safe Event Bus)
Tüm 6 çekirdek modül ve öz-koruma katmanı JSON/Struct formatında telemetri
paketleri yayınlayarak gevşek bağlı (decoupled) biçimde haberleşir.
"""

from __future__ import annotations
import asyncio
import json
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


@dataclass(slots=True)
class TelemetryPacket:
    """Modüller arası standart telemetri veri yapısı."""
    source_module: str
    event_type: str
    severity: str = "INFO"          # INFO, LOW, MEDIUM, HIGH, CRITICAL
    pid: Optional[int] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    packet_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


SubscriberCallback = Callable[[TelemetryPacket], Any]


class EventBus:
    """
    Çok iş parçacıklı ve asyncio uyumlu merkezi olay veri yolu.
    Abone olan modüllere olay türüne veya wildcard ('*') aboneliklerine göre paket dağıtır.
    """

    def __init__(self, max_history: int = 2000) -> None:
        self._lock = threading.RLock()
        self._subscribers: Dict[str, List[SubscriberCallback]] = {}
        self._history: deque[TelemetryPacket] = deque(maxlen=max_history)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def attach_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loop = loop

    def subscribe(self, event_type: str, callback: SubscriberCallback) -> None:
        with self._lock:
            self._subscribers.setdefault(event_type, []).append(callback)

    def publish(self, packet: TelemetryPacket) -> None:
        """Hem senkron hem asenkron aboneleri güvenli şekilde tetikler."""
        with self._lock:
            self._history.append(packet)
            targets = list(self._subscribers.get(packet.event_type, []))
            targets.extend(self._subscribers.get("*", []))
            loop = self._loop

        for cb in targets:
            try:
                if asyncio.iscoroutinefunction(cb):
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(cb(packet), loop)
                else:
                    cb(packet)
            except Exception as exc:
                # Olay veri yolunun hata nedeniyle kilitlenmesini engeller
                err_pkt = TelemetryPacket(
                    source_module="EVENT_BUS",
                    event_type="BUS_DISPATCH_ERROR",
                    severity="LOW",
                    payload={"error": str(exc), "failed_event": packet.event_type}
                )
                with self._lock:
                    self._history.append(err_pkt)

    def emit(
        self,
        source_module: str,
        event_type: str,
        severity: str = "INFO",
        pid: Optional[int] = None,
        **payload: Any
    ) -> TelemetryPacket:
        pkt = TelemetryPacket(
            source_module=source_module,
            event_type=event_type,
            severity=severity,
            pid=pid,
            payload=payload
        )
        self.publish(pkt)
        return pkt

    def get_history(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._history)
        if event_type:
            items = [p for p in items if p.event_type == event_type]
        return [p.to_dict() for p in items[-limit:]]
