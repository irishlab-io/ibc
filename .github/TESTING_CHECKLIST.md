# Security Remediation Testing Checklist

This checklist should be used when reviewing and testing the GitHub Actions security fixes.

## Pre-Merge Review Checklist

### 1. Code Review
- [ ] Review all workflow changes in `.github/workflows/`
- [ ] Verify permissions are appropriately scoped
- [ ] Confirm all actions are pinned to commit SHAs
- [ ] Check that no secrets are exposed in workflow definitions
- [ ] Verify security scan implementations look correct

### 2. Documentation Review
- [ ] Read `.github/SECURITY_PRACTICES.md`
- [ ] Review `.github/SECURITY_FIXES_SUMMARY.md`
- [ ] Understand all vulnerabilities that were fixed
- [ ] Confirm recommendations are appropriate

### 3. Workflow Validation
- [ ] All YAML files are syntactically valid (already verified ✅)
- [ ] Workflow triggers are appropriate
- [ ] Job dependencies are correct
- [ ] Concurrency groups are properly configured

## Post-Merge Testing Checklist

### 1. Pull Request Workflow (`pr.yml`)
- [ ] Trigger a test PR to verify workflow runs
- [ ] Verify pre-commit checks execute
- [ ] Confirm SAST (Bandit) scan runs and produces output
- [ ] Confirm SCA (pip-audit) scan runs and produces output
- [ ] Verify container build succeeds
- [ ] Verify Trivy container scan runs
- [ ] Check that SARIF files are uploaded to Security tab
- [ ] Verify secret scanning (GitGuardian) runs
- [ ] Confirm workflow completes successfully

Expected output locations:
```
- Bandit report: Console output + bandit-report.json artifact
- pip-audit report: Console output + sca-report.json artifact
- Trivy results: GitHub Security tab (SARIF format)
```

### 2. Main Branch Workflow (`main.yml`)
- [ ] Push a commit to main branch
- [ ] Verify all security scans run (SAST, SCA, Container)
- [ ] Check container image is built and pushed
- [ ] Verify SARIF uploads to Security tab
- [ ] Confirm smoke tests pass
- [ ] Verify release workflow triggers correctly

### 3. Branch Workflow (`branch.yml`)
- [ ] Push to a feature branch (e.g., `feat/test`)
- [ ] Verify SAST and SCA scans run
- [ ] Confirm container build executes
- [ ] Verify Trivy scan runs (table format)
- [ ] Check that workflow completes

### 4. Deployment Workflow (`cd.yml`)
- [ ] Trigger a manual deployment
- [ ] Verify SBOM generation (Syft) runs
- [ ] Confirm SBOM scanning (Grype) executes
- [ ] Check that SARIF results upload to Security tab
- [ ] Verify deployment succeeds without secret exposure
- [ ] Confirm CF_TUNNEL_TOKEN is passed as env var, not file

### 5. Pages Workflow (`pages.yml`)
- [ ] Make a change to docs/ or mkdocs.yml
- [ ] Verify workflow triggers
- [ ] Check that cache key is correctly formatted
- [ ] Confirm MkDocs deployment succeeds

### 6. Tag Workflow (`tag.yml`)
- [ ] Create a test tag (e.g., `v0.0.1-test`)
- [ ] Verify release workflow runs
- [ ] Confirm changelog is generated
- [ ] Check GitHub release is created

## Security Verification

### 1. GitHub Security Tab
- [ ] Navigate to `Security > Code scanning`
- [ ] Verify Trivy scan results appear
- [ ] Check Grype SBOM scan results appear
- [ ] Confirm alerts are actionable
- [ ] Review any critical/high findings

### 2. Permissions Check
- [ ] Review workflow run logs for permission errors
- [ ] Confirm no workflows have excessive permissions
- [ ] Verify read-only permissions work where expected
- [ ] Check that security-events write permission works

### 3. Secret Protection
- [ ] Review all workflow logs for exposed secrets
- [ ] Confirm secrets are properly masked
- [ ] Verify no .env files are created in workflows
- [ ] Check that secrets are passed as environment variables only

### 4. Supply Chain Security
- [ ] Verify all actions use commit SHA references
- [ ] Check that external workflow reference is commented out
- [ ] Confirm no `@latest` or `@main` tags are used
- [ ] Review Dependabot alerts for action updates

## Scan Output Validation

### Expected SAST (Bandit) Output
```
Run started...
[main]  INFO    profile include tests: None
[main]  INFO    profile exclude tests: None
[main]  INFO    running on Python X.XX.X

Test results:
>> Issue: [B106:hardcoded_password_funcarg] Possible hardcoded password
   Severity: Low   Confidence: Medium
```

### Expected SCA (pip-audit) Output
```
Found X known vulnerabilities in Y packages
┌───────────────┬─────────────────┬───────────┬───────────┬────────────────┐
│ Name          │ Version         │ ID        │ Fix       │ Description    │
├───────────────┼─────────────────┼───────────┼───────────┼────────────────┤
│ package-name  │ 1.0.0           │ CVE-...   │ 1.0.1     │ Vulnerability  │
└───────────────┴─────────────────┴───────────┴───────────┴────────────────┘
```

### Expected Trivy Output
```
Scanning image...
Total: X (CRITICAL: Y, HIGH: Z)
┌───────────────┬─────────────┬──────────┬───────────────────┐
│ Library       │ Vulnerability│ Severity │ Installed Version │
├───────────────┼─────────────┼──────────┼───────────────────┤
│ library       │ CVE-...     │ CRITICAL │ 1.0.0             │
└───────────────┴─────────────┴──────────┴───────────────────┘
```

### Expected SBOM Output
```
✓ SBOM cataloged: 150 packages
✓ Syft generated sbom.spdx.json
✓ Grype scanning for vulnerabilities...
NAME    INSTALLED   FIXED-IN   TYPE   VULNERABILITY   SEVERITY
pkg     1.0.0       1.0.1      pypi   CVE-...         High
```

## Performance Check

### Workflow Duration Expectations
- [ ] PR workflow: < 20 minutes
- [ ] Main workflow: < 25 minutes
- [ ] Branch workflow: < 15 minutes
- [ ] CD workflow: < 20 minutes
- [ ] Pages workflow: < 5 minutes
- [ ] Tag workflow: < 5 minutes

### Resource Usage
- [ ] No workflows timing out
- [ ] Cache hit rates are reasonable
- [ ] Build times are acceptable
- [ ] No unnecessary rebuilds

## Failure Scenarios

### Test Security Gates Work Correctly
- [ ] Introduce a test secret in code → GitGuardian should block
- [ ] Add a vulnerable dependency → pip-audit should detect
- [ ] Add insecure Python code → Bandit should flag
- [ ] Use vulnerable base image → Trivy should find vulnerabilities

### Verify Proper Failure Handling
- [ ] Security scan failure blocks pipeline
- [ ] Error messages are clear and actionable
- [ ] No `continue-on-error` on security steps
- [ ] Exit codes properly propagate

## Rollback Plan

If issues are discovered:

1. **Critical Issues**
   - Revert the PR immediately
   - Document the issue
   - Fix and re-test before re-deploying

2. **Non-Critical Issues**
   - Create issue to track
   - Document workaround if needed
   - Fix in follow-up PR

3. **Partial Rollback**
   - Can selectively revert specific workflow changes
   - Keep documentation updates
   - Re-apply security fixes incrementally

## Sign-Off

### Required Approvals
- [ ] Security team review
- [ ] DevOps team review
- [ ] At least one full test run completed successfully
- [ ] All critical/high scan findings triaged
- [ ] Documentation approved

### Final Checks
- [ ] All checklist items completed
- [ ] No regressions in functionality
- [ ] Security posture improved
- [ ] Team trained on new processes

---

**Date Tested**: __________________  
**Tested By**: __________________  
**Issues Found**: __________________  
**Status**: ⬜ Approved  ⬜ Needs Fixes  ⬜ Blocked

## Notes

_Add any additional observations, issues, or recommendations here:_

---

For questions or issues, refer to:
- [SECURITY_PRACTICES.md](.github/SECURITY_PRACTICES.md) - Technical details
- [SECURITY_FIXES_SUMMARY.md](.github/SECURITY_FIXES_SUMMARY.md) - Executive summary
