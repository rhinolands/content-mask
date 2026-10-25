"""Each README promise, as a test."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scan import scan_text

ROOT = Path(__file__).resolve().parent.parent
EMPTY: dict = {}


@pytest.mark.parametrize(
    "text",
    [
        "server at 10.0.0.12",
        "mail me at someone@example.org",
        "nic 00:1A:2b:3C:4d:5E",
        "call 054-1234567",
        "call +972 54 1234567",
    ],
)
def test_builtin_blocks_fire_with_empty_config(text):
    assert scan_text(text, EMPTY).blocked


def test_clean_text_passes():
    r = scan_text("A short post about gateways.", EMPTY)
    assert not r.blocked
    assert r.hits == []


def test_config_patterns_add_to_builtins():
    mapping = {"block_patterns": [r"[a-z0-9-]+\.lab\.home"]}
    assert scan_text("see caddy.lab.home", mapping).blocked
    assert scan_text("see 10.0.0.1", mapping).blocked


def test_known_name_is_masked_any_case():
    mapping = {"clients": [{"real": "Acme Research", "pseudonym": "a lab"}]}
    r = scan_text("Work for ACME research this year.", mapping)
    assert "a lab" in r.masked
    assert "acme" not in r.masked.lower()
    assert r.needs_double_gate
    assert not r.blocked


def test_masking_never_hides_a_block():
    mapping = {"clients": [{"real": "host 10.1.2.3", "pseudonym": "a host"}]}
    r = scan_text("Moved to host 10.1.2.3 today.", mapping)
    assert r.masked == "Moved to a host today."
    assert r.blocked


def test_pseudonym_is_literal():
    mapping = {"clients": [{"real": "Acme", "pseudonym": r"\1 \g<0>"}]}
    assert scan_text("Acme", mapping).masked == r"\1 \g<0>"


def test_malformed_pattern_fails_closed():
    with pytest.raises(re.error):
        scan_text("anything", {"block_patterns": ["("]})


def run_cli(text: str, tmp_path: Path, mapping: dict | None = None):
    work = tmp_path / "gate"
    work.mkdir()
    (work / "scan.py").write_text((ROOT / "scan.py").read_text())
    (work / "client-map.example.json").write_text(
        (ROOT / "client-map.example.json").read_text()
    )
    if mapping is not None:
        (work / "client-map.local.json").write_text(json.dumps(mapping))
    return subprocess.run(
        [sys.executable, str(work / "scan.py")],
        input=text,
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_exits_2_when_blocked(tmp_path):
    assert run_cli("ping 192.168.1.1", tmp_path).returncode == 2


def test_cli_exits_0_when_clean(tmp_path):
    assert run_cli("nothing to see", tmp_path).returncode == 0


def test_cli_bad_config_pattern_exits_nonzero(tmp_path):
    r = run_cli("nothing to see", tmp_path, {"block_patterns": ["("]})
    assert r.returncode not in (0, 2)


def test_cli_prefers_local_map(tmp_path):
    mapping = {"clients": [{"real": "Zeta", "pseudonym": "a firm"}]}
    r = run_cli("Zeta", tmp_path, mapping)
    assert "client-map.local.json" in r.stdout
    assert "a firm" in r.stdout
