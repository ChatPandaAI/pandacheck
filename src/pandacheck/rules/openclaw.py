from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pandacheck.models import Finding, Severity

Rule = Callable[[dict[str, Any]], list[Finding]]

LOCAL_PROVIDERS = {"ollama", "lmstudio", "llama.cpp", "llamacpp", "local"}
DANGEROUS_TOOLS = {"exec", "process", "write", "edit", "apply_patch", "browser", "gateway"}


def _nested(config: dict[str, Any], *keys: str, default: Any = None) -> Any:
    value: Any = config
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def _model_provider(model_ref: Any) -> str | None:
    if not isinstance(model_ref, str) or "/" not in model_ref:
        return None
    return model_ref.split("/", 1)[0].strip().lower()


def _model_config(config: dict[str, Any]) -> tuple[Any, list[Any]]:
    model = _nested(config, "agents", "defaults", "model")
    if isinstance(model, str):
        return model, []
    if isinstance(model, dict):
        fallbacks = model.get("fallbacks", [])
        if not isinstance(fallbacks, list):
            fallbacks = []
        return model.get("primary"), fallbacks
    return None, []


def local_to_cloud_fallback(config: dict[str, Any]) -> list[Finding]:
    primary, fallbacks = _model_config(config)
    primary_provider = _model_provider(primary)
    if primary_provider not in LOCAL_PROVIDERS:
        return []

    remote_fallbacks = [
        fallback
        for fallback in fallbacks
        if (provider := _model_provider(fallback)) is not None and provider not in LOCAL_PROVIDERS
    ]
    if not remote_fallbacks:
        return []

    return [
        Finding(
            rule_id="PC001",
            severity=Severity.WARNING,
            title="Local model can fall back to a remote provider",
            message=(
                "The primary model is local, but at least one configured fallback appears to use "
                "a non-local provider. This can change privacy, network, or cost expectations when "
                "the primary model fails."
            ),
            evidence={"primary": primary, "remote_fallbacks": remote_fallbacks},
            remediation=(
                "Remove remote fallbacks if local-only operation is required, or explicitly document "
                "and govern the fallback path."
            ),
        )
    ]


def unsandboxed_dangerous_tools(config: dict[str, Any]) -> list[Finding]:
    sandbox_mode = _nested(config, "agents", "defaults", "sandbox", "mode", default="off")
    allowed = _nested(config, "tools", "allow", default=[])
    if not isinstance(allowed, list):
        return []

    dangerous = sorted({tool for tool in allowed if isinstance(tool, str)} & DANGEROUS_TOOLS)
    if sandbox_mode != "off" or not dangerous:
        return []

    return [
        Finding(
            rule_id="PC002",
            severity=Severity.HIGH,
            title="Dangerous tools are explicitly allowed while sandboxing is off",
            message=(
                "The default agent sandbox is off while powerful host-affecting tools are explicitly "
                "allowed. A compromised or mistaken agent may have a larger blast radius."
            ),
            evidence={"sandbox_mode": sandbox_mode, "dangerous_tools": dangerous},
            remediation=(
                "Enable sandboxing for the relevant agents, narrow the allow-list, and deny host-level "
                "exec/write capabilities that are not required."
            ),
        )
    ]


def shared_sandbox_scope(config: dict[str, Any]) -> list[Finding]:
    scope = _nested(config, "agents", "defaults", "sandbox", "scope")
    if scope != "shared":
        return []

    return [
        Finding(
            rule_id="PC003",
            severity=Severity.WARNING,
            title="Sandbox scope is shared across agents",
            message=(
                "A shared sandbox scope can allow separate agents to operate in the same container or "
                "workspace, weakening cross-agent isolation."
            ),
            evidence={"sandbox_scope": scope},
            remediation=(
                "Use scope 'agent' for per-agent isolation or 'session' when each session should receive "
                "a separate sandbox."
            ),
        )
    ]


OPENCLAW_RULES: tuple[Rule, ...] = (
    local_to_cloud_fallback,
    unsandboxed_dangerous_tools,
    shared_sandbox_scope,
)
