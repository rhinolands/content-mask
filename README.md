# content-mask

A **default-deny privacy gate** for AI-generated content.

Before any draft — a LinkedIn post, a document, an LLM output — leaves your machine, pipe it through `content-mask`. It **masks known names** (client / customer → pseudonym) and **blocks** on confidential patterns (IPs, emails, MAC addresses, phone numbers, internal hostnames).

Built for the common case: you generate content with an LLM and need a *hard guarantee* that nothing sensitive slips into something public.

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
- Phone numbers

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

---

By **Gustavo Norymberg** — AI & Agentic Platform Architect. [LinkedIn](https://www.linkedin.com/in/gustavonorymberg)
