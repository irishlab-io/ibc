"""Generate an AI-assisted remediation starter for a Snyk issue."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-path", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--github-output", required=True)
    return parser.parse_args()


def parse_markers(issue_body: str) -> dict[str, str]:
    """Extract machine-readable markers from an issue body."""
    matches = re.findall(r"<!--\s*([^:]+):\s*(.*?)\s*-->", issue_body)
    return {key.strip(): value.strip() for key, value in matches}


def slugify(value: str) -> str:
    """Create a Git-friendly slug."""
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def request_ai_remediation(metadata: dict[str, str]) -> dict[str, Any]:
    """Request a remediation starter from GitHub Models when configured."""
    token = os.environ.get("GH_MODELS_TOKEN")
    if not token:
        return deterministic_remediation(metadata, reason="GH_MODELS_TOKEN is not configured.")

    model = os.environ.get("GH_MODELS_MODEL") or "openai/gpt-4.1-mini"
    payload = {
        "model": model,
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You generate concise dependency-remediation starter plans for GitHub pull requests. "
                    "Return strict JSON with keys summary, rationale, proposed_changes, files_to_review, "
                    "verification_steps, and notes. Keep every value concise and practical."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(metadata),
            },
        ],
    }

    request = urllib.request.Request(
        url="https://models.github.ai/inference/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request) as response:
            raw_response = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        return deterministic_remediation(metadata, reason=f"GitHub Models request failed: {exc.code} {details}")
    except urllib.error.URLError as exc:
        return deterministic_remediation(metadata, reason=f"GitHub Models request failed: {exc}")

    response_payload = json.loads(raw_response)
    content = response_payload["choices"][0]["message"]["content"]
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return deterministic_remediation(metadata, reason="GitHub Models returned non-JSON content.")

    parsed["notes"] = list(parsed.get("notes") or [])
    parsed["notes"].append(f"Generated with GitHub Models model `{model}`.")
    return parsed


def deterministic_remediation(metadata: dict[str, str], reason: str) -> dict[str, Any]:
    """Build a deterministic fallback remediation starter."""
    fixed_version = metadata["fixed_version"]
    recommendation = (
        f"Upgrade `{metadata['package']}` to `{fixed_version}` or later in `{metadata['manifest']}`."
        if fixed_version and "Review the Snyk recommendation" not in fixed_version
        else f"Review the vulnerable dependency path for `{metadata['package']}` in `{metadata['manifest']}`."
    )
    return {
        "summary": f"Prepare a starter remediation for `{metadata['package']}` ({metadata['vulnerability_id']}).",
        "rationale": (
            f"The Snyk issue reports a critical dependency vulnerability in `{metadata['manifest']}` "
            f"for `{metadata['package']}` version `{metadata['current_version']}`."
        ),
        "proposed_changes": [
            recommendation,
            "Regenerate lockfiles or exported dependency manifests after the version change.",
            "Review impacted tests or runtime compatibility after the dependency update.",
        ],
        "files_to_review": [
            metadata["manifest"],
            "pyproject.toml",
            "uv.lock",
        ],
        "verification_steps": [
            "python -m uv run pytest -m 'not e2e'",
            "python -m uv run pre-commit run actionlint --files .github/workflows/*.yml",
        ],
        "notes": [
            "Fallback starter generated without a live GitHub Models response.",
            reason,
        ],
    }


def write_prompt_file(
    workspace: Path,
    issue_number: int,
    issue_title: str,
    metadata: dict[str, str],
    remediation: dict[str, Any],
    run_url: str,
) -> Path:
    """Write the AI-generated remediation starter file."""
    package_slug = slugify(metadata["package"])[:40] or "dependency"
    output_dir = workspace / ".github" / "prompt" / "snyk"
    output_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = output_dir / f"issue-{issue_number}-{package_slug}.md"

    lines = [
        f"# Snyk remediation starter for issue #{issue_number}",
        "",
        "> This file was generated automatically from a Snyk-labeled GitHub issue.",
        "> It is a starting point for review and follow-up code changes, not an approved fix.",
        "",
        "## Source issue",
        "",
        f"- Title: {issue_title}",
        f"- Package: `{metadata['package']}`",
        f"- Current version: `{metadata['current_version']}`",
        f"- Vulnerability ID: `{metadata['vulnerability_id']}`",
        f"- Manifest: `{metadata['manifest']}`",
        f"- Suggested fixed version: `{metadata['fixed_version']}`",
        f"- Workflow run: {run_url}",
        "",
        "## Summary",
        "",
        str(remediation["summary"]),
        "",
        "## Rationale",
        "",
        str(remediation["rationale"]),
        "",
        "## Proposed change idea",
        "",
    ]

    for item in remediation.get("proposed_changes") or []:
        lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "## Files to review",
            "",
        ]
    )
    for item in remediation.get("files_to_review") or []:
        lines.append(f"- `{item}`")

    lines.extend(
        [
            "",
            "## Verification",
            "",
        ]
    )
    for item in remediation.get("verification_steps") or []:
        lines.append(f"- `{item}`")

    lines.extend(
        [
            "",
            "## Notes",
            "",
        ]
    )
    for item in remediation.get("notes") or []:
        lines.append(f"- {item}")

    prompt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return prompt_path


def write_pr_body(issue_number: int, prompt_path: Path, metadata: dict[str, str], remediation: dict[str, Any]) -> str:
    """Write a temporary pull request body file."""
    body = [
        "## Summary",
        f"- add an AI-generated remediation starter for Snyk issue #{issue_number}",
        f"- capture a starting change idea for `{metadata['package']}` in `{prompt_path.as_posix()}`",
        "- keep this PR as a draft for human review before any production dependency update",
        "",
        "## Issue",
        f"- Refs #{issue_number}",
        f"- Vulnerability: `{metadata['vulnerability_id']}`",
        f"- Affected manifest: `{metadata['manifest']}`",
        "",
        "## Notes",
        "- This PR was generated from an issue labeled `snyk` and `ai-remediation`.",
        f"- Starter summary: {remediation['summary']}",
    ]

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".md") as handle:
        handle.write("\n".join(body) + "\n")
        return handle.name


def main() -> int:
    """Program entrypoint."""
    args = parse_args()
    with open(args.event_path, encoding="utf-8") as handle:
        event = json.load(handle)

    issue = event["issue"]
    issue_number = int(issue["number"])
    issue_title = str(issue["title"])
    markers = parse_markers(issue.get("body") or "")

    required = [
        "snyk-package",
        "snyk-current-version",
        "snyk-manifest",
        "snyk-vuln-id",
        "snyk-fixed-version",
    ]
    missing = [key for key in required if key not in markers]
    if missing:
        raise ValueError(f"Missing Snyk issue markers: {', '.join(missing)}")

    metadata = {
        "package": markers["snyk-package"],
        "current_version": markers["snyk-current-version"],
        "manifest": markers["snyk-manifest"],
        "vulnerability_id": markers["snyk-vuln-id"],
        "fixed_version": markers["snyk-fixed-version"],
        "issue_number": str(issue_number),
        "issue_title": issue_title,
        "issue_url": issue["html_url"],
    }
    remediation = request_ai_remediation(metadata)

    package_slug = slugify(metadata["package"])[:24] or "dependency"
    branch_name = f"automation/snyk-issue-{issue_number}-{package_slug}"
    pr_title = f"draft: remediation starter for snyk issue #{issue_number} ({metadata['package']})"

    workspace = Path(args.workspace)
    prompt_path = write_prompt_file(
        workspace=workspace,
        issue_number=issue_number,
        issue_title=issue_title,
        metadata=metadata,
        remediation=remediation,
        run_url=args.run_url,
    )
    pr_body_path = write_pr_body(
        issue_number=issue_number,
        prompt_path=prompt_path,
        metadata=metadata,
        remediation=remediation,
    )

    outputs = {
        "branch-name": branch_name,
        "prompt-path": prompt_path.relative_to(workspace).as_posix(),
        "pr-title": pr_title,
        "pr-body-path": pr_body_path,
    }
    with open(args.github_output, "a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"::error::{exc}", file=sys.stderr)
        raise
