# SBOM (Software Bill of Materials) Generation and Scanning

## Overview

This project implements automated SBOM generation and vulnerability scanning as part of the CI/CD pipeline. The SBOM provides a comprehensive inventory of all software components, dependencies, and their versions, which is essential for security compliance and supply chain security.

## Tools Used

- **Syft**: Generates SBOM from the codebase in multiple formats
- **Grype**: Scans SBOM for known vulnerabilities in dependencies

## SBOM Generation

### When SBOMs are Generated

SBOMs are automatically generated during the release process when a version tag is pushed (e.g., `v0.2.0`). This happens in the `.github/workflows/tag.yml` workflow.

### SBOM Formats

Two SBOM formats are generated for each release:

1. **SPDX JSON** (`sbom-vX.Y.Z.spdx.json`) - Software Package Data Exchange format, an industry standard
2. **CycloneDX JSON** (`sbom-vX.Y.Z.cyclonedx.json`) - Another widely-used SBOM standard

### Generation Process

1. When a tag is pushed (e.g., `v0.2.0`), the tag workflow is triggered
2. Syft is installed on the runner
3. Syft scans the entire project directory and generates SBOMs
4. Both SBOM files are attached to the GitHub release

### Accessing SBOMs

SBOMs are available as release assets:
- Go to the [Releases page](https://github.com/irishlab-io/ibc/releases)
- Select the desired version
- Download the SBOM files from the "Assets" section

## Vulnerability Scanning

### When Scanning Occurs

Vulnerability scanning is performed during the CD (Continuous Deployment) pipeline in `.github/workflows/cd.yml`. This ensures that before deploying to any environment, the dependencies are checked for known vulnerabilities.

### Scanning Process

1. The deployment workflow downloads the SBOM from the GitHub release
2. Grype scans the SBOM for known vulnerabilities
3. The scan checks against the CVE (Common Vulnerabilities and Exposures) database
4. Vulnerabilities are categorized by severity: Low, Medium, High, Critical

### Severity Thresholds

The pipeline is configured to:
- **Fail** on HIGH or CRITICAL severity vulnerabilities
- **Warn** on MEDIUM and LOW severity vulnerabilities
- **Continue** with deployment after manual review if needed

### Vulnerability Reports

When vulnerabilities are detected:

1. A detailed report is generated in both JSON and text formats
2. The report is uploaded as a workflow artifact
3. The scan results are displayed in the workflow logs
4. If high/critical vulnerabilities are found, the deployment step is warned

### Viewing Vulnerability Reports

To access vulnerability reports:

1. Go to the workflow run in GitHub Actions
2. Scroll to the "Artifacts" section at the bottom
3. Download `vulnerability-report-{env}` (where `{env}` is `dev` or `prod`)
4. The artifact contains:
   - `vulnerability-report.json` - Machine-readable format
   - `vulnerability-report.txt` - Human-readable table format
   - `sbom.spdx.json` - The SBOM that was scanned

## Manual SBOM Generation

You can generate an SBOM manually for local development:

```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM in SPDX format
syft dir:. -o spdx-json=sbom.spdx.json

# Generate SBOM in CycloneDX format
syft dir:. -o cyclonedx-json=sbom.cyclonedx.json
```

## Manual Vulnerability Scanning

You can scan the SBOM manually:

```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan an SBOM file
grype sbom:sbom.spdx.json

# Scan with specific output format
grype sbom:sbom.spdx.json -o table
grype sbom:sbom.spdx.json -o json

# Fail on specific severity
grype sbom:sbom.spdx.json --fail-on high
grype sbom:sbom.spdx.json --fail-on critical
```

## Compliance and Security Best Practices

### Why SBOM Matters

1. **Supply Chain Security**: Know exactly what components are in your application
2. **Vulnerability Management**: Quickly identify affected components when new CVEs are disclosed
3. **Compliance**: Meet regulatory requirements (e.g., Executive Order 14028)
4. **Incident Response**: Faster response when security incidents occur
5. **License Compliance**: Track open source licenses used in the project

### Recommendations

1. **Review vulnerability reports** before deploying to production
2. **Update dependencies** regularly to patch known vulnerabilities
3. **Monitor security advisories** for components in your SBOM
4. **Archive SBOMs** for each release for audit trails
5. **Integrate with security tools** that can consume SBOM formats

## Troubleshooting

### SBOM Not Found During Deployment

If the CD pipeline fails to download the SBOM:

1. Verify the release was created with attached SBOM files
2. Check the version tag format matches `vX.Y.Z`
3. Ensure the release is public or the workflow has proper permissions
4. For first deployments, the SBOM may not exist yet

### High Number of Vulnerabilities

If many vulnerabilities are reported:

1. Check if they affect production dependencies (not dev dependencies)
2. Update the affected packages to patched versions
3. If updates aren't available, assess if the vulnerability is exploitable in your context
4. Consider using alternative packages if necessary

### False Positives

Grype may report false positives:

1. Review the CVE details to understand the vulnerability
2. Check if your usage pattern is affected
3. You can suppress specific vulnerabilities if they're not applicable
4. Document the reasoning for any suppressions

## References

- [Syft Documentation](https://github.com/anchore/syft)
- [Grype Documentation](https://github.com/anchore/grype)
- [SPDX Specification](https://spdx.dev/)
- [CycloneDX Specification](https://cyclonedx.org/)
- [NIST Software Supply Chain Security](https://www.nist.gov/itl/executive-order-improving-nations-cybersecurity)
