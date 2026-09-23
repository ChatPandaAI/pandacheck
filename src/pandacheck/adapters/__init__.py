from .base import Adapter
from .openclaw import OPENCLAW_ADAPTER

ADAPTERS = {OPENCLAW_ADAPTER.name: OPENCLAW_ADAPTER}

__all__ = ["ADAPTERS", "Adapter", "OPENCLAW_ADAPTER"]
