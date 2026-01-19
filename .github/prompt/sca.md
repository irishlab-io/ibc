# SCA - Prompt

You are updating the ibc repository to remediate PyYAML 5.3.1 vulnerabilities (e.g., CVE-2020-14343 arbitrary code execution via unsafe loaders).

Context

- Dependency pins live in [pyproject.toml](pyproject.toml) and [requirements.txt](requirements.txt); PyYAML is currently 5.3.1.
- Stack: Python ≥3.10, Django 4.2, tests via pytest (see [tests](tests) tree).
- Goal: eliminate unsafe YAML usage and upgrade to a secure PyYAML version with safe loaders/dumpers.

Tasks

1) Upgrade dependency:
   - Bump PyYAML to a secure current release. Update pins in [pyproject.toml](pyproject.toml) and [requirements.txt](requirements.txt) and refresh hashes (same format as current file). Regenerate the export/lock so versions match.
   - If uv/pip-tools is used, re-run the export to sync pins and hashes.

2) Inventory & hardening:
   - Search all code and tests for PyYAML usage (`yaml.load`, `yaml.safe_load`, `yaml.dump`, `yaml.safe_dump`, `Loader=`, `Dumper=`).
   - For any path handling untrusted or semi-trusted input, enforce safe parsing: use `yaml.safe_load` or `yaml.load(..., Loader=yaml.SafeLoader)`.
   - For dumping untrusted/back to disk, prefer `yaml.safe_dump` or `yaml.dump(..., Dumper=yaml.SafeDumper)`.
   - Remove/avoid `FullLoader`, `UnsafeLoader`, default loaders, or implicit loaders for external data.
   - If object construction is truly required, isolate it: minimal custom loader limited to required types, with comments documenting the trust boundary and justification.

3) Tests & verification:
   - Add/adjust tests to prove dangerous payloads are rejected on untrusted paths. Example payload: `!!python/object/apply:os.system ["echo exploit"]`.
   - Ensure unsafe tags raise an exception (or are sanitized) and do not execute. Assert behavior.
   - Run `pytest` (respect repo settings) and report pass/fail. If slow, prioritize security/unit coverage for YAML paths.

4) Documentation & hygiene:
   - Note the PyYAML bump and loader hardening in [CHANGELOG](CHANGELOG.md) (or equivalent release notes) with a brief entry.
   - Keep changes scoped to YAML handling and dependency updates.

Deliverables / acceptance criteria

- PyYAML upgraded to a secure version in both dependency files; hashes/pins updated and in sync.
- No remaining unsafe loader usage for untrusted data paths.
- Tests added/updated to demonstrate rejection of unsafe YAML tags; pytest passes.
- Brief summary describing dependency bump and safety changes.
