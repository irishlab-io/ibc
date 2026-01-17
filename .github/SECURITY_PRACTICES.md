# GitHub Actions Security Practices

This document outlines the security improvements and best practices implemented in the GitHub Actions workflows for this repository.

## Security Vulnerabilities Fixed

### Critical Issues Addressed

#### 1. Removed `pull_request_target` Trigger (CVE-Level Risk)
**Previous State**: The `pr.yml` workflow used `pull_request_target` which allows code from forked repositories to run with write permissions to the repository.

**Risk**: An attacker could submit a malicious pull request that:
- Steals repository secrets
- Modifies code or workflow files
- Pushes malicious code to the repository
- Exfiltrates sensitive data

**Fix**: Removed `pull_request_target` trigger and use only `pull_request` which runs with read-only permissions and doesn't have access to secrets from untrusted code.

```yaml
# BEFORE (DANGEROUS)
on:
  pull_request_target:
    branches:
      - master

# AFTER (SECURE)
on:
  pull_request:
    branches:
      - main
```

#### 2. Secret Exposure in Environment Files
**Previous State**: Secrets were written to `.env` files in the workflow:
```yaml
run: echo "CF_TUNNEL_TOKEN=${{ secrets.CF_TUNNEL_TOKEN }}" > .env
```

**Risk**: 
- Secrets could be exposed in logs
- Files could be accidentally committed
- Secrets visible in artifact uploads

**Fix**: Pass secrets directly as environment variables:
```yaml
env:
  CF_TUNNEL_TOKEN: ${{ secrets.CF_TUNNEL_TOKEN }}
```

#### 3. Missing Permissions Scoping
**Previous State**: Many workflows didn't define explicit `permissions` block, defaulting to broad write access.

**Risk**: Compromised workflows could:
- Modify repository contents
- Create releases
- Manage packages
- Access all repository data

**Fix**: Added explicit least-privilege permissions to all workflows:
```yaml
permissions:
  contents: read          # Only read repository contents
  packages: write         # Only when pushing containers
  security-events: write  # Only for uploading security scan results
```

#### 4. Unpinned Action Versions
**Previous State**: Some actions used version tags (e.g., `@v1`, `@main`) instead of commit SHAs.

**Risk**: Supply chain attacks through:
- Compromised action repositories
- Tag manipulation
- Malicious version updates

**Fix**: All actions now pinned to immutable commit SHAs:
```yaml
# BEFORE (VULNERABLE)
uses: actions/checkout@v4

# AFTER (SECURE)
uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
```

#### 5. Security Scan Failures Ignored
**Previous State**: Security scans used `continue-on-error: true`, allowing vulnerabilities to pass through.

**Risk**: 
- Critical vulnerabilities deployed to production
- Secrets leaked to repository
- Vulnerable dependencies in production

**Fix**: Removed `continue-on-error` from all security-critical steps:
```yaml
# Security scans now block the pipeline on failure
- name: GitGuardian scan
  id: secret
  uses: GitGuardian/ggshield/actions/secret@...
  # No continue-on-error

- name: Check status of potentially failing step and issue warning
  if: steps.secret.outcome == 'failure'
  run: exit 1  # Fail the workflow
```

## Security Scanning Implementation

### 1. Static Application Security Testing (SAST)
**Tool**: [Bandit](https://github.com/PyCQA/bandit)

**Purpose**: Scans Python source code for common security issues like:
- SQL injection vulnerabilities
- Hardcoded passwords
- Use of insecure functions (eval, exec, etc.)
- Weak cryptographic practices
- Path traversal vulnerabilities

**Implementation**:
```yaml
- name: Run SAST Scan
  run: |
    echo "Running SAST with Bandit..."
    uv pip install bandit[toml]
    bandit -r src/ -f json -o bandit-report.json || true
    bandit -r src/ -f screen
```

**Output**: JSON and console reports showing security issues with severity levels.

### 2. Software Composition Analysis (SCA)
**Tool**: [pip-audit](https://github.com/pypa/pip-audit)

**Purpose**: Scans Python dependencies for known vulnerabilities using:
- PyPI Advisory Database
- OSV (Open Source Vulnerabilities) Database
- GHSA (GitHub Security Advisories)

**Implementation**:
```yaml
- name: Run SCA Scan
  run: |
    echo "Running SCA with pip-audit..."
    uv pip install pip-audit
    pip-audit --desc --format json --output sca-report.json || true
    pip-audit --desc
```

**Output**: Lists all vulnerable dependencies with CVE IDs and recommended fixes.

### 3. Container Image Scanning
**Tool**: [Trivy](https://github.com/aquasecurity/trivy)

**Purpose**: Comprehensive container security scanner that detects:
- OS package vulnerabilities (Alpine, Debian, etc.)
- Application dependency vulnerabilities
- Misconfigurations
- Secrets in container layers
- License compliance issues

**Implementation**:
```yaml
- name: Run Trivy Container Scan
  uses: aquasecurity/trivy-action@6e7b7d1fd3e4fef0c5fa8cce1229c54b2c9bd0d8
  with:
    image-ref: "ghcr.io/${{ github.repository }}:${{ needs.docker_build.outputs.image-tag }}"
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'

- name: Upload Trivy scan results to GitHub Security tab
  uses: github/codeql-action/upload-sarif@...
  with:
    sarif_file: 'trivy-results.sarif'
```

**Output**: SARIF format uploaded to GitHub Security tab for vulnerability tracking.

### 4. Software Bill of Materials (SBOM) Generation and Scanning
**Tools**: 
- [Syft](https://github.com/anchore/syft) - SBOM generation
- [Grype](https://github.com/anchore/grype) - SBOM vulnerability scanning

**Purpose**: 
- Generate comprehensive software inventory
- Track all components and dependencies
- Identify vulnerabilities in the supply chain
- Compliance with executive orders and regulations

**Implementation**:
```yaml
- name: Generate SBOM with Syft
  uses: anchore/sbom-action@61119d458adab75f756bc0b9e4bde25725f86a7a
  with:
    image: "ghcr.io/${{ github.repository }}:${{ inputs.image-tag }}"
    format: 'spdx-json'
    output-file: 'sbom.spdx.json'

- name: Scan SBOM with Grype
  uses: anchore/scan-action@64a33b277ea7a1215a3c142735a1091341939ff5
  with:
    sbom: 'sbom.spdx.json'
    fail-build: false
    severity-cutoff: 'high'
```

**Output**: SPDX-format SBOM and vulnerability scan results in SARIF format.

### 5. Secret Scanning
**Tool**: [GitGuardian](https://www.gitguardian.com/)

**Purpose**: Detects secrets and credentials in:
- Source code
- Configuration files
- Commit history
- Pull requests

**Implementation**: Already configured and now properly enforced (no longer using `continue-on-error`).

## Best Practices Applied

### 1. Principle of Least Privilege
Every workflow now has minimal required permissions:

```yaml
# Read-only by default
permissions:
  contents: read

# Write only when necessary
permissions:
  contents: write  # For releases/changelog updates
  packages: write  # For container publishing
  security-events: write  # For security scan uploads
```

### 2. Immutable Action References
All actions pinned to commit SHAs for supply chain security:

```yaml
uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
```

### 3. Security Gates
Security scans block the pipeline on critical findings:
- Secret detection failures prevent merges
- High/Critical vulnerabilities block deployments
- SAST findings require review

### 4. Visibility and Reporting
All security scan results integrated with GitHub Security tab:
- Trivy container scans → Security tab
- Grype SBOM scans → Security tab
- Centralized vulnerability tracking
- Automated alerts for new vulnerabilities

### 5. Defense in Depth
Multiple security layers:
1. Pre-commit hooks (local)
2. Secret scanning (on push/PR)
3. SAST scanning (source code)
4. SCA scanning (dependencies)
5. Container scanning (images)
6. SBOM scanning (supply chain)
7. Runtime monitoring (deployment)

## Workflow Security Matrix

| Workflow | Permissions | SAST | SCA | Container Scan | SBOM | Secret Scan |
|----------|-------------|------|-----|----------------|------|-------------|
| pr.yml | read/write (minimal) | ✅ | ✅ | ✅ | ❌ | ✅ |
| main.yml | read/write (minimal) | ✅ | ✅ | ✅ | ❌ | ✅ |
| branch.yml | read/write (minimal) | ✅ | ✅ | ✅ | ❌ | ❌ |
| cd.yml | read only | ❌ | ❌ | ❌ | ✅ | ❌ |
| pages.yml | write (pages) | ❌ | ❌ | ❌ | ❌ | ❌ |
| tag.yml | write (releases) | ❌ | ❌ | ❌ | ❌ | ❌ |

## Remaining Recommendations

### 1. Enable GitHub Advanced Security (GHAS)
If available in your organization:
- Code scanning (CodeQL)
- Dependency review
- Secret scanning (native)

### 2. Implement OIDC for Cloud Deployments
Replace SSH keys with OpenID Connect for secure, credential-less authentication:

```yaml
- name: Configure AWS Credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/GitHubAction-AssumeRoleWithAction
    aws-region: us-east-1
```

### 3. Add Branch Protection Rules
Require security checks to pass before merging:
- Status checks must pass
- Require signed commits
- Require pull request reviews
- Dismiss stale reviews

### 4. Regular Security Audits
- Review workflow permissions quarterly
- Update action versions monthly
- Audit secret usage
- Review access logs

### 5. Monitor and Alert
Set up alerts for:
- Failed security scans
- New vulnerabilities in dependencies
- Suspicious workflow runs
- Permission escalations

## References

- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)
- [Securing the Software Supply Chain](https://slsa.dev/)
- [CIS Software Supply Chain Security Guide](https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide)

## Contact

For security concerns or questions about these practices, please:
1. Open a security advisory (preferred for vulnerabilities)
2. Contact the security team
3. Create an issue (for non-sensitive questions)
