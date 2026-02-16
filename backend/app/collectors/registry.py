"""
Collector Registry — maps collector names to their classes.

To add a new collector:
1. Create the file (e.g., screenshot_collector.py)
2. Import and register it here
3. The pipeline picks it up automatically
"""

from __future__ import annotations

from typing import Type

from app.collectors.base import BaseCollector
from app.collectors.dns_collector import DNSCollector
from app.collectors.http_collector import HTTPCollector
from app.collectors.tls_collector import TLSCollector
from app.collectors.whois_collector import WHOISCollector
from app.collectors.asn_collector import ASNCollector
from app.collectors.intel_collector import IntelCollector
from app.collectors.vt_collector import VTCollector


COLLECTOR_REGISTRY: dict[str, Type[BaseCollector]] = {
    "dns": DNSCollector,
    "http": HTTPCollector,
    "tls": TLSCollector,
    "whois": WHOISCollector,
    "asn": ASNCollector,
    "intel": IntelCollector,
    "vt": VTCollector,
}


def get_collector(name: str) -> Type[BaseCollector] | None:
    """Look up a collector class by name."""
    return COLLECTOR_REGISTRY.get(name)


def available_collectors() -> list[str]:
    """List all registered collector names."""
    return list(COLLECTOR_REGISTRY.keys())
