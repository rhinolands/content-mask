# content-mask

A **default-deny privacy gate** for AI-generated content.

Before any draft — a LinkedIn post, a document, an LLM output — leaves your machine, pipe it through `content-mask`. It **masks known names** (client / customer → pseudonym) and **blocks** on confidential patterns. Built in: IPv4, email, MAC and Israeli phone numbers. Internal hostnames and codenames come from your config.

Built for the common case: you generate content with an LLM and want a hard stop before it goes public.
It is a regex gate. It only catches what its patterns describe. Anything else passes.

## Why default-deny

The gate is **never weaker than the code**:

- **Built-in block patterns fire even if the config supplies none** — you can't accidentally configure the safety away.
- **Masking never suppresses block detection** — blocks are scanned on the *original* text, so a mask can't hide a leak.
- **A malformed config pattern fails _closed_** — a bad regex makes the gate refuse to run rather than pass unsafe text.
- **Case-insensitive throughout** — a different casing of a name can't bypass the mask.

## Built-in blocks

- IPv4 addresses (including private ranges)
- Email addresses
- MAC addresses
- Israeli phone numbers (`05X-XXXXXXX` and `+972 …`). Other formats need a config pattern.

Add your own (internal hostnames, project codenames, …) via config.

## Usage — as a pipeline gate

```bash
echo "draft text…" | python scan.py
# exits 2 if blocked, 0 if clean → chain it:
generate_draft | python scan.py && publish
```

Output: the masked text, whether it was **blocked**, whether it needs a **second human review** (a known name was masked), and every **hit** (what matched and why).

## Config

Copy `client-map.example.json` → `client-map.local.json` (keep it **gitignored**) and add:

```json
{
  "clients":        [ {"real": "Real Name", "pseudonym": "a generic descriptor"} ],
  "block_patterns": [ "your-internal-host\\.example\\.com" ]
}
```

`scan.py` uses `client-map.local.json` if present, else falls back to the example.

## Tests

```bash
pip install pytest ruff
pytest
ruff check . && ruff format --check .
```

Each promise above has a test in `tests/test_scan.py`. CI runs them plus a gitleaks scan over every commit.

---

By **Gustavo Norymberg** — AI & Agentic Platform Architect. [LinkedIn](https://www.linkedin.com/in/gustavonorymberg)
