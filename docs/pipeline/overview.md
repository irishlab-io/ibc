---
hide:
  - toc
---

# Pipeline Overview

The **Insecure Bank Corp** project uses GitHub Actions for CI|CD platform. The pipeline is designed to ensure code quality, security, and reliable deployments through multiple stages of validation.

The CI/CD strategy follows a **branch-based workflow** with four distinct pipelines triggered by different Git events:

| Pipeline      | Trigger                      | Description                                         | Status                                                                                                                                                                                                        |
|---------------|------------------------------|-----------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CI - Branches | Push to various branches     | Early feedback during development                   | [![CI - Branches](https://github.com/mighty-muffin/ibc/actions/workflows/branch.yml/badge.svg)](https://github.com/mighty-muffin/ibc/actions/workflows/branch.yml)                                            |
| CI - PR       | PR to `main`                 | Comprehensive validation before merge               | [![CI - PR](https://github.com/mighty-muffin/ibc/actions/workflows/pr.yml/badge.svg)](https://github.com/mighty-muffin/ibc/actions/workflows/pr.yml)                                                          |
| CI - Main     | Push to `main` branch        | Full validation, container build & publish, release | [![CI - Main](https://github.com/mighty-muffin/ibc/actions/workflows/main.yml/badge.svg)](https://github.com/mighty-muffin/ibc/actions/workflows/main.yml)                                                    |
| CI - Tag      | Version tags (`v*`)          | Semantic release and changelog publication          | [![CI - Tag](https://github.com/mighty-muffin/ibc/actions/workflows/tag.yml/badge.svg)](https://github.com/mighty-muffin/ibc/actions/workflows/tag.yml)                                                       |
| Dependabot    | Weekly (7 days cooldown)     | Regular updates for dependencies                    | [![Dependabot Updates](https://github.com/mighty-muffin/ibc/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/mighty-muffin/ibc/actions/workflows/dependabot/dependabot-updates) |

Most pipelines shares these core stages:

```mermaid
---
title: Common Pipeline Stages
---
%%{ init:
        {  'logLevel': 'debug',
            'theme': 'dark'
        }
}%%

flowchart LR

  subgraph core[Core Stages]
    direction LR
    commit[Trigger] --> pre-commit[Pre-Commit Checks]
    pre-commit --> build[Build & Tests] --> gating[Gating]
    pre-commit --> security[Vulnerabilities Scan] --> gating --> release[Release]

  end
```

At a high level, once a git commit is pushed to the remote repository the various triggers different actions:

- **Pre-Commit:** Check for linting, formatting, and code quality checks
- **Build Phase:** Run the build, test and container packaging
- **Security Phase:** Run the SDLC, Secret, SAST, SCA and Container scanning
- **Gating Phase:** Check if any failure occurs during the Security Phase
- **Release Phase:** Trigger the package release once code is merged to `main`
- **SBOM Generation:** Generate Software Bill of Materials for releases
- **Vulnerability Scanning:** Scan SBOM for known vulnerabilities before deployment

For detailed information about SBOM generation and vulnerability scanning, see [SBOM Documentation](sbom.md).

## Reusable Workflows and Composite Actions

**Reusable Workflows** create a level of abstraction in the workflow definition allowing easier governance at scale.
**Composite Actions** simplify complexe and compressed multi-steps operations into a single block.

```yml
# ...
  hello:
    name: Call Hello World Reusable Workflow
    uses: mighty-muffin/.github/.github/workflows/reusable-hello-world.yml@main
#...
  pre-commit:
    steps:
      - name: Run Pre-Commit Checks
        id: precommit
        uses: ./.github/actions/precommit
        with:
          skip: "pytest, uv-export"
        continue-on-error: true
# ...
```

## Concurrency Control

All pipelines implement concurrency control to prevent duplicate runs.  This ensures only the latest commit is processed when multiple pushes occur in quick succession.

```yml
concurrency:
  group: ${{ github.workflow }}-${{ github.head_ref || github.run_id }}
  cancel-in-progress: true
```

## Build Platform

This project leverage both `amd64` and `arm64` build agent to ensure compatibility accros numerous computer platforms.

```yml
job_name:
  needs:
    - <required-steps>
  name: <Job Name>
  runs-on: ${{ matrix.os }}
  strategy:
    fail-fast: false
    matrix:
      os: [ubuntu-24.04, ubuntu-24.04-arm]
  timeout-minutes: 10
```
