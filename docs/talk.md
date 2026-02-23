# Talk

## Welcome

```bash
uv venv .venv --python 3.10 --clear && source .venv/bin/activate
uv sync && uv build --verbose
```

## Some tools

```bash
syft scan docker.io/python:3.10.11-bullseye --output cyclonedx-json=sbom.json
grype sbom:sbom.json
```

## SBOM Central Command

Talk about DTrack a bit...

## Let's ship a container

```bash
docker build . --tag ibc
syft scan ibc --output cyclonedx-json=sbom.json
grype sbom:sbom.json
```

DTrack = API-friendly

```bash
curl -X "POST" "https://dependencytrack.local.irishlab.io" \
  -H "Content-Type: multipart/form-data" \
  -H "X-Api-Key: ${DEPENDENCY_TRACK}$" \
  -F "autoCreate=true" \
  -F "projectName=A-demo-test" \
  -F "projectVersion=0.0.1" \
  -F "bom=@sbom.json"
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
