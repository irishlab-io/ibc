# Talk

uvx uv-upgrade

## Welcome

```bash
uv venv .venv --python 3.10 --clear && source .venv/bin/activate
uv sync && uv build --verbose
```

## Let's ship a container

```bash
docker build . --tag ibc
syft scan ibc -o json=sbom.json
grype sbom:sbom.json
```

## Fixing packages vuln

```bash
uvx pip-audit -r requirements.txt --aliases
uvx uv-upgrade
```

---

## Command

```bash
echo
```

## Reference

- [Pip-Audit](https://github.com/pypa/pip-audit); audits Python environments, requirements files and dependency trees for known security vulnerabilities, and can automatically fix them
- [Syft](https://github.com/anchore/syft); a CLI tool and library for generating a Software Bill of Materials from container images and filesystems
- [Grype](https://github.com/anchore/grype); A vulnerability scanner for container images and filesystems
