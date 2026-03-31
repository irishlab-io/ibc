"""Context processors for adding version information to templates."""

import os
import subprocess
from typing import Any


def version_info(request) -> dict[str, Any]:
    """
    Context processor to provide version information to all templates.

    Returns:
        Dictionary with git_commit and repo_url keys
    """
    return {
        "git_commit": get_git_commit(),
        "repo_url": get_repo_url(),
    }


def get_git_commit() -> str:
    """Get the short git commit hash from git or environment variable."""
    # First try environment variable (set during Docker build)
    env_commit = os.environ.get("GIT_COMMIT", "")
    if env_commit:
        return env_commit

    # Fall back to git command
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                stderr=subprocess.DEVNULL,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )
            .decode("utf-8")
            .strip()
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def get_repo_url() -> str:
    """Get the repository URL from environment variable or git remote origin."""
    # First try environment variable (set during Docker build)
    env_repo_url = os.environ.get("REPO_URL", "")
    if env_repo_url:
        return env_repo_url

    try:
        repo_url = (
            subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                stderr=subprocess.DEVNULL,
                cwd=os.path.dirname(os.path.dirname(__file__)),
            )
            .decode("utf-8")
            .strip()
        )

        # Convert SSH URL to HTTPS if needed
        if repo_url.startswith("git@"):
            # Convert git@github.com:owner/repo.git to https://github.com/owner/repo
            repo_url = repo_url.replace("git@", "https://").replace(".com:", ".com/")
            repo_url = repo_url.removesuffix(".git")

        return repo_url
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
