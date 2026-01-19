# CHANGELOG

## Security Update - January 2026

### PyYAML Security Remediation
- **Version Upgrade**: Updated PyYAML from 5.3.1 to 6.0.1
- **Security Fix**: Addresses CVE-2020-14343 (arbitrary code execution via unsafe loaders)
- **Hardening**: All YAML operations now enforce safe loading/dumping practices
- **Testing**: Added comprehensive security tests to verify unsafe payloads are rejected



## v0.2.0 (2026-01-16)

### Feat

- migrate legacy code to gh (#2)

## v0.1.0 (2026-01-16)

### Feat

- code commits

## v0.0.1 (2026-01-16)

### Feat

- Initial commits
