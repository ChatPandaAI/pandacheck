import json
from pathlib import Path

from pandacheck.cli import main
from pandacheck.policy import load_policy

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_json_output(capsys):
    code = main(["scan", str(FIXTURES / "cloud_fallback.json5"), "--format", "json"])
    output = json.loads(capsys.readouterr().out)
    assert code == 1
    assert output["schema_version"] == "1"
    assert output["pandacheck_version"] == "0.2.1"
    assert output["adapter"] == "openclaw"
    assert output["fail_on"] == "info"
    assert output["findings"][0]["rule_id"] == "PC001"


def test_cli_clean_exit(capsys):
    code = main(["scan", str(FIXTURES / "safe.json5")])
    assert code == 0
    output = capsys.readouterr().out
    assert "PandaCheck adapter: openclaw" in output
    assert "No active PandaCheck findings" in output


def test_cli_high_threshold_allows_warning(capsys):
    code = main([
        "scan",
        str(FIXTURES / "cloud_fallback.json5"),
        "--fail-on",
        "high",
    ])
    assert code == 0
    assert "PC001" in capsys.readouterr().out


def test_cli_high_threshold_fails_high(capsys):
    code = main([
        "scan",
        str(FIXTURES / "wildcard_tools.json5"),
        "--fail-on",
        "high",
    ])
    assert code == 1
    assert "PC005" in capsys.readouterr().out


def test_cli_never_threshold_never_fails_on_findings(capsys):
    code = main([
        "scan",
        str(FIXTURES / "wildcard_tools.json5"),
        "--fail-on",
        "never",
    ])
    assert code == 0
    assert "PC005" in capsys.readouterr().out


def test_cli_policy_suppresses_with_reason(capsys):
    code = main([
        "scan",
        str(FIXTURES / "cloud_fallback.json5"),
        "--policy",
        str(FIXTURES / "policy_accept_cloud.json5"),
        "--format",
        "json",
    ])
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["findings"] == []
    assert output["suppressed_findings"][0]["finding"]["rule_id"] == "PC001"
    assert "Approved availability fallback" in output["suppressed_findings"][0]["reason"]


def test_cli_policy_adapter_conflict_is_error(capsys):
    code = main([
        "scan",
        str(FIXTURES / "safe.json5"),
        "--policy",
        str(FIXTURES / "policy_accept_cloud.json5"),
        "--adapter",
        "openclaw",
    ])
    assert code == 0


def test_cli_diff_fails_only_on_new_high_findings(capsys):
    code = main([
        "diff",
        str(FIXTURES / "safe.json5"),
        str(FIXTURES / "realistic_overbroad.json5"),
        "--fail-on",
        "high",
        "--format",
        "json",
    ])
    output = json.loads(capsys.readouterr().out)
    assert code == 1
    assert output["mode"] == "diff"
    assert {item["rule_id"] for item in output["introduced"]} >= {"PC005", "PC006"}


def test_cli_diff_passes_when_risk_is_only_resolved(capsys):
    code = main([
        "diff",
        str(FIXTURES / "realistic_overbroad.json5"),
        str(FIXTURES / "safe.json5"),
        "--fail-on",
        "high",
        "--format",
        "json",
    ])
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["introduced"] == []
    assert len(output["resolved"]) == 7


def test_cli_diff_policy_keeps_exception_visible(capsys):
    code = main([
        "diff",
        str(FIXTURES / "safe.json5"),
        str(FIXTURES / "cloud_fallback.json5"),
        "--policy",
        str(FIXTURES / "policy_accept_cloud.json5"),
        "--format",
        "json",
    ])
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["introduced"] == []
    assert output["candidate_suppressed_findings"][0]["finding"]["rule_id"] == "PC001"


def test_cli_init_creates_loadable_policy(tmp_path, capsys):
    path = tmp_path / "pandacheck.policy.json5"
    code = main(["init", str(path)])
    assert code == 0
    policy = load_policy(path)
    assert policy.adapter == "openclaw"
    assert policy.fail_on == "high"
    output = capsys.readouterr().out
    assert "Created PandaCheck policy" in output
    assert "pandacheck scan YOUR_CONFIG" in output


def test_cli_init_refuses_overwrite_without_force(tmp_path, capsys):
    path = tmp_path / "pandacheck.policy.json5"
    path.write_text("keep me", encoding="utf-8")
    code = main(["init", str(path)])
    assert code == 2
    assert path.read_text(encoding="utf-8") == "keep me"
    assert "Refusing to overwrite" in capsys.readouterr().err


def test_cli_init_force_overwrites(tmp_path, capsys):
    path = tmp_path / "pandacheck.policy.json5"
    path.write_text("old", encoding="utf-8")
    code = main([
        "init",
        str(path),
        "--adapter",
        "openclaw",
        "--fail-on",
        "warning",
        "--force",
    ])
    assert code == 0
    policy = load_policy(path)
    assert policy.fail_on == "warning"
    capsys.readouterr()
