"""DNS checker package exports."""

from __future__ import annotations

from .base import DNSChecker
from .records import RecordCheck

__all__ = ["DNSChecker", "RecordCheck"]
