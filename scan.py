"""Privacy gate (spec §7). Default-deny: mask known clients, BLOCK on
confidential patterns. Built in: IPv4, email, MAC, Israeli phone numbers.
Internal hostnames and other strings come from the config's block_patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Built-in default-deny patterns. These fire even when the map supplies no
# block_patterns, so the gate is never weaker than the code. Map patterns MERGE
# with (do not replace) these. Case-insensitive matching is applied at scan time.
DEFAULT_BLOCK_PATTERNS = [
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # any IPv4 (incl. private)
    r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",  # email address
    r"\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b",  # MAC address
    r"\b05\d[-\s]?\d{7}\b",  # Israeli mobile (05X-XXXXXXX)
    r"\+972[-\s]?\d{1,2}[-\s]?\d{7}\b",  # intl Israeli phone (+972…)
]


@dataclass
class MaskResult:
    masked: str
    blocked: bool
    needs_double_gate: bool
    hits: list[tuple[str, str]] = field(default_factory=list)  # (text, kind)


def scan_text(text: str, mapping: dict) -> MaskResult:
    hits: list[tuple[str, str]] = []

    # 1. Mask known clients (real -> pseudonym). A client hit is NOT a block,
    #    but escalates to the double-gate tier. Case-insensitive so a different
    #    casing of the real name can't bypass the gate (C2). The replacement is
    #    a literal lambda so backslashes / group-refs in the pseudonym can't be
    #    interpreted as regex replacement syntax.
    needs_double_gate = False
    masked = text
    for c in mapping.get("clients", []):
        new_masked = re.sub(
            re.escape(c["real"]),
            lambda _m, p=c["pseudonym"]: p,
            masked,
            flags=re.IGNORECASE,
        )
        if new_masked != masked:
            masked = new_masked
            hits.append((c["real"], "client"))
            needs_double_gate = True

    # 2. Block on confidential patterns (IPs, internal hostnames, etc.).
    #    Scan the ORIGINAL text, not the masked string — masking must never
    #    suppress block detection (C1): a block reflects what was in the input.
    #    Case-insensitive so e.g. CADDY.LAB.HOME is caught (I1).
    #    NOTE: a malformed regex in block_patterns will raise re.error here;
    #    that is a fail-closed surface (the gate refuses to run), by design.
    blocked = False
    patterns = DEFAULT_BLOCK_PATTERNS + list(mapping.get("block_patterns", []))
    for pat in patterns:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            hits.append((m.group(0), "pattern"))
            blocked = True

    return MaskResult(
        masked=masked, blocked=blocked, needs_double_gate=needs_double_gate, hits=hits
    )


if __name__ == "__main__":
    # Pipeline gate: read draft from stdin, mask + scan, print result.
    # Exits 2 if blocked (default-deny), so it can be chained in a pipeline.
    import json
    import sys
    from pathlib import Path

    here = Path(__file__).resolve().parent
    map_path = here / "client-map.local.json"
    if not map_path.exists():
        map_path = here / "client-map.example.json"
    mapping = json.loads(map_path.read_text())

    text = sys.stdin.read()
    r = scan_text(text, mapping)

    print(f"--- masked draft (using {map_path.name}) ---")
    print(r.masked)
    print("--- gate ---")
    print(f"blocked:          {r.blocked}")
    print(f"needs_double_gate: {r.needs_double_gate}")
    if r.hits:
        print("hits:")
        for value, kind in r.hits:
            print(f"  [{kind}] {value!r}")
    else:
        print("hits:             none")

    sys.exit(2 if r.blocked else 0)
