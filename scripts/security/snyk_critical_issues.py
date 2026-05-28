"""Create or update GitHub issues for critical Snyk findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

LABEL_DEFINITIONS = {
    "security": {
        "color": "d73a4a",
        "description": "Security vulnerability tracking",
    },
    "snyk": {
        "color": "5319e7",
        "description": "Created from Snyk critical vulnerability scans",
    },
    "ai-remediation": {
        "color": "0e8a16",
        "description": "Eligible for AI-generated remediation starter pull requests",
    },
}


@dataclass(frozen=True)
class Finding:
    """A critical Snyk finding ready to be synchronized into GitHub."""

    key: str
    title: str
    body: str
    labels: list[str]


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--workflow-name", required=True)
    parser.add_argument("--issue-labels", default="security,snyk,ai-remediation")
    return parser.parse_args()


def api_request(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
) -> Any:
    """Send an authenticated GitHub API request."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
    }

    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url=url,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request) as response:
            raw_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            return None
        if exc.code == 422 and method == "POST" and url.endswith("/labels"):
            return None
        raise RuntimeError(f"GitHub API request failed: {exc.code} {details}") from exc

    if not raw_body:
        return None
    return json.loads(raw_body)


def load_results(path: str) -> list[dict[str, Any]]:
    """Load Snyk JSON results into a list of project results."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict) and "vulnerabilities" in data:
        return [data]
    if isinstance(data, dict) and "results" in data:
        return list(data["results"])
    if isinstance(data, list):
        return data

    raise ValueError(f"Unsupported Snyk JSON structure in {path}")


def slugify(value: str) -> str:
    """Create a GitHub-friendly slug fragment."""
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def extract_manifest(project: dict[str, Any]) -> str:
    """Extract the manifest path from a Snyk project result."""
    return (
        project.get("displayTargetFile")
        or project.get("targetFile")
        or project.get("projectName")
        or "requirements.txt"
    )


def extract_fixed_version(vulnerability: dict[str, Any]) -> str:
    """Extract the nearest fixed version from a Snyk vulnerability."""
    nearest_fixed = vulnerability.get("nearestFixedInVersion")
    if nearest_fixed:
        return str(nearest_fixed)

    fixed_in = vulnerability.get("fixedIn") or []
    if fixed_in:
        return str(fixed_in[0])

    for upgrade in vulnerability.get("upgradePath") or []:
        if not upgrade or "@" not in upgrade:
            continue
        _, candidate = upgrade.rsplit("@", 1)
        if candidate:
            return candidate

    return "Review the Snyk recommendation in the workflow run output."


def extract_identifiers(vulnerability: dict[str, Any]) -> str:
    """Build a readable identifier string."""
    identifiers = vulnerability.get("identifiers") or {}
    values: list[str] = []
    for source in ("CVE", "CWE", "GHSA"):
        entries = identifiers.get(source) or []
        values.extend(entries)
    return ", ".join(values) if values else "No additional CVE/CWE/GHSA identifiers reported."


def build_findings(
    projects: list[dict[str, Any]],
    issue_labels: list[str],
    run_url: str,
    workflow_name: str,
) -> list[Finding]:
    """Convert Snyk project results into critical issue payloads."""
    findings: list[Finding] = []

    for project in projects:
        manifest = extract_manifest(project)

        for vulnerability in project.get("vulnerabilities") or []:
            severity = str(vulnerability.get("severity", "")).lower()
            if severity != "critical":
                continue

            package_name = str(vulnerability.get("packageName") or vulnerability.get("name") or "unknown")
            version = str(vulnerability.get("version") or "unknown")
            vulnerability_id = str(vulnerability.get("id") or slugify(vulnerability.get("title", "unknown")))
            fixed_version = extract_fixed_version(vulnerability)
            finding_key = hashlib.sha256(
                f"{package_name}|{version}|{vulnerability_id}|{manifest}".encode("utf-8")
            ).hexdigest()[:16]

            title = f"[snyk][critical] {package_name} {version} - {vulnerability_id}"
            recommendation = (
                f"Upgrade `{package_name}` from `{version}` to `{fixed_version}` or later."
                if fixed_version != "Review the Snyk recommendation in the workflow run output."
                else fixed_version
            )
            package_manager = project.get("packageManager") or "pip"
            project_name = project.get("projectName") or manifest

            body_lines = [
                f"<!-- snyk-finding-key: {finding_key} -->",
                f"<!-- snyk-package: {package_name} -->",
                f"<!-- snyk-current-version: {version} -->",
                f"<!-- snyk-manifest: {manifest} -->",
                f"<!-- snyk-vuln-id: {vulnerability_id} -->",
                f"<!-- snyk-fixed-version: {fixed_version} -->",
                f"<!-- snyk-package-manager: {package_manager} -->",
                "",
                "## Critical Snyk vulnerability",
                "",
                f"- Package: `{package_name}`",
                f"- Current version: `{version}`",
                f"- Severity: `{severity}`",
                f"- Vulnerability ID: `{vulnerability_id}`",
                f"- Affected manifest: `{manifest}`",
                f"- Package manager: `{package_manager}`",
                f"- Project: `{project_name}`",
                f"- Additional identifiers: {extract_identifiers(vulnerability)}",
                "",
                "## Recommended remediation",
                "",
                f"- {recommendation}",
                "",
                "## Snyk summary",
                "",
                f"- Title: {vulnerability.get('title', 'No title reported by Snyk')}",
                f"- Description: {vulnerability.get('description', 'No description reported by Snyk')}",
                "",
                "## Traceability",
                "",
                f"- Workflow: `{workflow_name}`",
                f"- Workflow run: {run_url}",
                "",
                "_This issue is managed automatically by the Snyk critical vulnerability workflow._",
            ]

            findings.append(
                Finding(
                    key=finding_key,
                    title=title,
                    body="\n".join(body_lines),
                    labels=issue_labels,
                )
            )

    deduplicated: dict[str, Finding] = {}
    for finding in findings:
        deduplicated[finding.key] = finding
    return list(deduplicated.values())


def ensure_labels(repo_api_url: str, token: str, labels: list[str]) -> None:
    """Ensure the expected labels exist in the repository."""
    for label_name in labels:
        label_url = f"{repo_api_url}/labels/{urllib.parse.quote(label_name, safe='')}"
        if api_request("GET", label_url, token) is not None:
            continue

        definition = LABEL_DEFINITIONS.get(
            label_name,
            {"color": "ededed", "description": "Automation label"},
        )
        api_request(
            "POST",
            f"{repo_api_url}/labels",
            token,
            {
                "name": label_name,
                "color": definition["color"],
                "description": definition["description"],
            },
        )


def fetch_all_issues(repo_api_url: str, token: str) -> list[dict[str, Any]]:
    """Fetch all repository issues for deduplication."""
    page = 1
    issues: list[dict[str, Any]] = []
    while True:
        url = f"{repo_api_url}/issues?state=all&per_page=100&page={page}"
        page_items = api_request("GET", url, token) or []
        issues.extend(page_items)
        if len(page_items) < 100:
            return issues
        page += 1


def sync_finding(
    repo_api_url: str,
    token: str,
    finding: Finding,
    existing_issues: list[dict[str, Any]],
) -> str:
    """Create or update a GitHub issue for a finding."""
    marker = f"<!-- snyk-finding-key: {finding.key} -->"
    matching_issue = next(
        (
            issue
            for issue in existing_issues
            if "pull_request" not in issue and marker in (issue.get("body") or "")
        ),
        None,
    )

    payload = {
        "title": finding.title,
        "body": finding.body,
        "labels": finding.labels,
        "state": "open",
    }

    if matching_issue is None:
        api_request("POST", f"{repo_api_url}/issues", token, payload)
        return "created"

    issue_number = matching_issue["number"]
    api_request("PATCH", f"{repo_api_url}/issues/{issue_number}", token, payload)
    return "updated"


def main() -> int:
    """Program entrypoint."""
    args = parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN must be set.")

    repo_api_url = f"{args.api_url}/repos/{args.repo}"
    issue_labels = [label.strip() for label in args.issue_labels.split(",") if label.strip()]

    projects = load_results(args.input)
    findings = build_findings(
        projects=projects,
        issue_labels=issue_labels,
        run_url=args.run_url,
        workflow_name=args.workflow_name,
    )

    ensure_labels(repo_api_url=repo_api_url, token=token, labels=issue_labels)

    if not findings:
        print("No critical Snyk findings detected.")
        return 0

    existing_issues = fetch_all_issues(repo_api_url=repo_api_url, token=token)
    created = 0
    updated = 0

    for finding in findings:
        status = sync_finding(
            repo_api_url=repo_api_url,
            token=token,
            finding=finding,
            existing_issues=existing_issues,
        )
        if status == "created":
            created += 1
        else:
            updated += 1

    print(f"Synchronized {len(findings)} Snyk issues ({created} created, {updated} updated).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"::error::{exc}", file=sys.stderr)
        raise
