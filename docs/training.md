# Formation

uvx uv-upgrade --profile with_pinned

Application Security Testing (AST) is the process of finding and fixing security vulnerabilities in software throughout the development lifecycle (SDLC) to make apps resilient to threats like injection attacks, data breaches, and unauthorized access, using methods like SAST (code analysis), DAST (runtime testing), SCA (dependency scanning), and manual pen testing to secure applications before attackers exploit them.

AST integrates automated tools and manual checks into existing workflows (DevSecOps) to systematically scan, analyze, and report risks in code, dependencies, and configurations, securing the application from development through deployment.

**Key Types of AST:**

- Software Composition Analysis (**SCA**): Checks third-party libraries and open-source components for known vulnerabilities.
- Static Application Security Testing (**SAST**): Analyzes source code (white-box) for flaws like insecure coding, finding issues early, even before compilation.
- Dynamic Application Security Testing (**DAST**): Tests the running application (black-box) by simulating attacks from the outside to find runtime vulnerabilities.
- Interactive Application Security Testing (**IAST**): Combines SAST and DAST by analyzing code and runtime behavior simultaneously.
- Manual Penetration Testing: **Red Teams & Ethical hackers** simulate real-world attacks to find complex vulnerabilities.

**Why It is Important:**

- Shifts Left: Finds flaws early in the SDLC, making them cheaper and faster to fix.
- Protects Data: Prevents data breaches, system crashes, and financial losses.
- Ensures Compliance: Helps meet security standards and regulations.
- Reduces Risk: Makes applications more resistant to exploitation and ensures integrity.

## Common Weakness Enumeration

CWE primarily means Common Weakness Enumeration, a community-developed list by MITRE Corporation that catalogs general software and hardware flaws (weaknesses) that can lead to security vulnerabilities, like SQL Injection (CWE-89) or Cross-Site Scripting (CWE-79). It provides a standard language for identifying types of coding mistakes, unlike CVE (Common Vulnerabilities and Exposures), which lists specific instances of vulnerabilities. CWE helps developers understand and fix underlying coding issues to prevent future exploits, with lists like the CWE Top 25 Most Dangerous Software Weaknesses highlighting prevalent problems.

- What it is: A dictionary or catalog of common coding errors (weaknesses) in software and hardware.
- Purpose: To classify and describe the root causes of vulnerabilities, helping teams prevent them.
- Examples: CWE-89 (SQL Injection), CWE-79 (Cross-Site Scripting).
- Relation to CVE: A CVE points to a specific vulnerability (e.g., Log4j), while its CWE points to the general weakness type (e.g., Expression Language Injection).

## Common Vulnerabilities and Exposures

CVE stands for Common Vulnerabilities and Exposures, a widely recognized list of publicly known cybersecurity flaws, providing unique identifiers (like CVE-2024-XXXX) for each vulnerability, helping security teams, researchers, and organizations quickly identify, track, and patch security weaknesses in software and hardware. It acts as a universal dictionary for these flaws, improving communication and enabling efficient remediation across different security tools and databases.

Think of CVE as a public catalog of "known security holes" in software, each with its own specific number and details, making it easier for everyone in cybersecurity to talk about the same problem and find the fix.

**Key aspects of CVE:**

- Identification: Each vulnerability gets a unique ID (e.g., CVE-YYYY-NNNN).
- Description: Provides a brief description of the flaw and a link to public references.
- Standardization: Creates a common language for security data, improving interoperability between security products.
- Data Source: Feeds into other databases, like the NIST National Vulnerability Database (NVD).
- Purpose: Helps organizations prioritize and address security risks by understanding what vulnerabilities exist.

---

## Command

```bash
uv venv .venv --python 3.10 --clear && source .venv/bin/activate

uv sync && uv build --verbose

uv run pytest

uvx zizmor .github/ --min-severity high

uvx bandit --recursive src/web/views.py

uvx pip-audit -r requirements.txt --aliases

docker scout recommendations local://ibc

syft scan ibc -o cyclonedx-json > sbom.json

grype sbom:sbom.json -o table
```

## Reference

- [Bandit](https://github.com/PyCQA/bandit); a tool designed to find common security issues in Python code
- [Pip-Audit](https://github.com/pypa/pip-audit); audits Python environments, requirements files and dependency trees for known security vulnerabilities, and can automatically fix them
- [Zizmor](https://github.com/zizmorcore/zizmor); a static analysis tool for GitHub Actions workflows
- [Docker Scout](https://github.com/docker/scout-cli); supply chain and vulnerabilitis analysis tool or Docker container
- [Syft](https://github.com/anchore/syft); a CLI tool and library for generating a Software Bill of Materials from container images and filesystems
- [Grype](https://github.com/anchore/grype); A vulnerability scanner for container images and filesystems
