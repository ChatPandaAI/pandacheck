from pandacheck.adapters.base import Adapter
from pandacheck.rules import OPENCLAW_RULES

OPENCLAW_ADAPTER = Adapter(
    name="openclaw",
    rules=OPENCLAW_RULES,
    description="OpenClaw JSON5 configuration adapter",
)
