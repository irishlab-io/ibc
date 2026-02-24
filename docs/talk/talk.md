# Talk

## Welcome

- Vulnerability Management: Quickly identify which applications are affected when new vulnerabilities are discovered
- License Compliance: Track open source licenses across your organization
- Supply Chain Security: Understand your software’s dependency tree
- Regulatory Compliance: Meet requirements like US Executive Order 14028, Canadian Bill C-26, and many industry standards and best practices

- CycloneDX (OWASP)
- SPDX (Linux Foundation)
- SWID Tags (ISO/IEC 19770-2)

## Some tools

Syft is a powerful CLI tool and library for generating SBOMs from container images and filesystems. It supports multiple formats.
Grype is a vulnerability scanner that works hand-in-hand with Syft. It can scan container images, filesystems, and SBOMs to identify known vulnerabilities from multiple databases.

```bash
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
syft version
grype version
```

```bash
syft scan docker.io/python:3.10.11-bullseye --output cyclonedx-json=sbom.json
grype sbom:sbom.json
```

## SBOM Central Command

Talk about DTrack a bit...

## Let's ship a container

Talk about IBC a little bit.

```bash
uv venv .venv --python 3.10 --clear && source .venv/bin/activate
uv sync && uv build --verbose
```

Build the first version of IBC

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
# fix pyproject.toml
docker build . --tag ibc
syft scan ibc --output cyclonedx-json=sbom.json
```

## Reduce exposed surface

Let's not bundle the whole of `debian`, ship `alpine`

```bash
docker build . --tag ibc
syft scan ibc --output cyclonedx-json=sbom.json
```

## Harden image

The myth of cve-free image

```bash
docker build . --tag ibc
syft scan ibc --output cyclonedx-json=sbom.json
```

## Someone is messing with us

Fixing self-inflicted vulnerabilities

```bash
docker build . --tag ibc
syft scan ibc --output cyclonedx-json=sbom.json
```

## Wrap up

1. Generates your SBOM during CI
2. Store your SBOM in a central location (DTrack is nice and free)
3. Implement simple and easy Policies
4. Move the needle down
5. Look into harden images

---

## Reference

- [Syft](https://github.com/anchore/syft); a CLI tool and library for generating a Software Bill of Materials from container images and filesystems
- [Grype](https://github.com/anchore/grype); A vulnerability scanner for container images and filesystems
