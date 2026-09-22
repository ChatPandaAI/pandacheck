from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pandacheck.models import Finding, Severity

Rule = Callable[[dict[str, Any]], list[Finding]]

LOCAL_PROVIDERS = {"ollama", "lmstudio", "llama.cpp", "llamacpp", "local"}
DANGEROUS_TOOLS = {"exec", "process", "write", "edit", "apply_patch", "browser", "gateway"}
SECRET_KEYWORDS = ("token", "secret", "password", "api_key", "apikey", "credential", "private_key")


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


def _walk(obj: Any, path: tuple[str, ...] = ()):
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = path + (str(key),)
            yield child, value
            yield from _walk(value, child)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _walk(value, path + (str(index),))


def local_to_cloud_fallback(config: dict[str, Any]) -> list[Finding]:
    primary, fallbacks = _model_config(config)
    primary_provider = _model_provider(primary)
    if primary_provider not in LOCAL_PROVIDERS:
        return []
    remote_fallbacks = [
        fallback for fallback in fallbacks
        if (provider := _model_provider(fallback)) is not None and provider not in LOCAL_PROVIDERS
    ]
    if not remote_fallbacks:
        return []
    return [Finding("PC001", Severity.WARNING, "Local model can fall back to a remote provider",
        "The primary model is local, but a configured fallback appears non-local. This can change privacy, network, or cost expectations.",
        {"primary": primary, "remote_fallbacks": remote_fallbacks},
        "Remove remote fallbacks for local-only operation, or explicitly document and govern the fallback path.")]


def unsandboxed_dangerous_tools(config: dict[str, Any]) -> list[Finding]:
    sandbox_mode = _nested(config, "agents", "defaults", "sandbox", "mode", default="off")
    allowed = _nested(config, "tools", "allow", default=[])
    if not isinstance(allowed, list):
        return []
    dangerous = sorted({tool for tool in allowed if isinstance(tool, str)} & DANGEROUS_TOOLS)
    if sandbox_mode != "off" or not dangerous:
        return []
    return [Finding("PC002", Severity.HIGH, "Dangerous tools are explicitly allowed while sandboxing is off",
        "Powerful host-affecting tools are explicitly allowed while the default sandbox is off.",
        {"sandbox_mode": sandbox_mode, "dangerous_tools": dangerous},
        "Enable sandboxing, narrow the allow-list, and deny host-level capabilities that are not required.")]


def shared_sandbox_scope(config: dict[str, Any]) -> list[Finding]:
    scope = _nested(config, "agents", "defaults", "sandbox", "scope")
    if scope != "shared":
        return []
    return [Finding("PC003", Severity.WARNING, "Sandbox scope is shared across agents",
        "A shared sandbox can weaken isolation between separate agents.",
        {"sandbox_scope": scope},
        "Use per-agent or per-session sandbox scope when isolation is expected.")]


def writable_sandbox_workspace(config: dict[str, Any]) -> list[Finding]:
    sandbox = _nested(config, "agents", "defaults", "sandbox", default={})
    if not isinstance(sandbox, dict) or sandbox.get("mode", "off") == "off":
        return []
    access = sandbox.get("workspaceAccess")
    if access not in {"rw", "read-write", "write"}:
        return []
    return [Finding("PC004", Severity.WARNING, "Sandbox has write access to the agent workspace",
        "Sandboxing limits host access, but writable workspace access can still let tool calls modify agent files.",
        {"workspace_access": access},
        "Prefer read-only or no workspace access unless writes are required.")]


def wildcard_tool_allow(config: dict[str, Any]) -> list[Finding]:
    allowed = _nested(config, "tools", "allow", default=[])
    if not isinstance(allowed, list) or not any(item in {"*", "all"} for item in allowed):
        return []
    return [Finding("PC005", Severity.HIGH, "Tool allow-list contains a wildcard",
        "A wildcard allow entry makes the effective capability boundary difficult to review.",
        {"tool_allow": allowed},
        "Replace wildcard access with an explicit least-privilege allow-list.")]


def embedded_secrets(config: dict[str, Any]) -> list[Finding]:
    paths: list[str] = []
    for path, value in _walk(config):
        if not path or not isinstance(value, str) or not value.strip():
            continue
        key = path[-1].lower().replace("-", "_")
        if any(word in key for word in SECRET_KEYWORDS):
            paths.append(".".join(path))
    if not paths:
        return []
    return [Finding("PC006", Severity.HIGH, "Possible secret values are embedded in configuration",
        "Keys that look like credentials contain inline string values. PandaCheck does not include the values in its report.",
        {"paths": sorted(paths)},
        "Move credentials to the platform's supported secret/credential mechanism and keep them out of checked-in config.")]


def permissive_gateway_binding(config: dict[str, Any]) -> list[Finding]:
    bind = _nested(config, "gateway", "bind")
    if not isinstance(bind, str) or bind.lower() not in {"0.0.0.0", "::", "all", "lan"}:
        return []
    return [Finding("PC007", Severity.WARNING, "Gateway appears reachable beyond loopback",
        "The gateway bind setting appears broader than localhost, increasing network exposure.",
        {"gateway_bind": bind},
        "Bind to loopback unless remote access is intentionally required and protected by authentication and network controls.")]


def unrestricted_agent_delegation(config: dict[str, Any]) -> list[Finding]:
    candidates = [
        _nested(config, "agents", "defaults", "subagents", "allowAgents"),
        _nested(config, "agents", "defaults", "delegation", "allowAgents"),
    ]
    wildcard = next((value for value in candidates if isinstance(value, list) and "*" in value), None)
    if wildcard is None:
        return []
    return [Finding("PC008", Severity.WARNING, "Agent delegation uses a wildcard allow-list",
        "Wildcard delegation can permit an agent to route work to any available agent rather than a reviewed set.",
        {"allow_agents": wildcard},
        "Use an explicit allow-list of agents that this agent is permitted to delegate to.")]


OPENCLAW_RULES: tuple[Rule, ...] = (
    local_to_cloud_fallback,
    unsandboxed_dangerous_tools,
    shared_sandbox_scope,
    writable_sandbox_workspace,
    wildcard_tool_allow,
    embedded_secrets,
    permissive_gateway_binding,
    unrestricted_agent_delegation,
)
