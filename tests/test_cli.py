import json
from pathlib import Path

from pandacheck.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_json_output(capsys):
    code = main(["scan", str(FIXTURES / "cloud_fallback.json5"), "--format", "json"])
    output = json.loads(capsys.readouterr().out)
    assert code == 1
    assert output["fail_on"] == "info"
    assert output["findings"][0]["rule_id"] == "PC001"


def test_cli_clean_exit(capsys):
    code = main(["scan", str(FIXTURES / "safe.json5")])
    assert code == 0
    assert "No PandaCheck findings" in capsys.readouterr().out


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
