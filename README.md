# mcp-scan

[![npm version](https://badge.fury.io/js/mcp-scan.svg)](https://badge.fury.io/js/mcp-scan)
[![npm downloads](https://img.shields.io/npm/dw/mcp-scan)](https://www.npmjs.com/package/mcp-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/gitlab.com/abanoub.rodolf/mcp-scan/badge)](https://securityscorecards.dev/viewer/?uri=gitlab.com/abanoub.rodolf/mcp-scan)
[![npm provenance](https://img.shields.io/badge/npm%20provenance-signed-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)

**Open-source security scanner for Model Context Protocol (MCP) servers.**

MCP servers run with full access to your filesystem, API keys, and network. mcp-scan audits every MCP server configuration on your system, detecting leaked secrets, prompt injection risks, supply-chain vulnerabilities, and data flow issues before they become incidents.

```bash
npx mcp-scan@latest
```

No installation. No sign-up. No telemetry. No data leaves your machine. Supply chain scanning makes registry lookups (npm, OSV.dev, GitHub API) - disable with `--offline`.

---

## Why mcp-scan?

MCP servers are the new attack surface for AI-powered development. They run silently alongside your AI tools with shell access, filesystem permissions, and network egress. A single malicious or misconfigured server can exfiltrate API keys, inject instructions into your AI sessions, or become a supply-chain entry point.

mcp-scan was built after analyzing hundreds of publicly available MCP server configs and finding patterns that existing security tools miss: credential relay, prompt injection via tool descriptions, typosquatting near popular packages, and data sent to unexpected endpoints.

---

## What It Detects

| Check | Severity | Description |
|-------|----------|-------------|
| Data Exfiltration | CRITICAL | Tool reads filesystem/DB/clipboard and sends data to a network endpoint |
| Credential Relay | HIGH | Environment variables or secrets passed to external APIs or processes |
| Known Malicious Package | CRITICAL | Config references packages on the known-bad list |
| Exposed Secret | CRITICAL | Hardcoded API keys, tokens, or passwords in config |
| Prompt Injection | HIGH | Instructions embedded in tool names, descriptions, or tool schema fields |
| Obfuscated Network | HIGH | Server uses base64, hex, or reversed URLs to hide endpoints |
| Data-in-URL Exfil | HIGH | Potential exfiltration via long strings in URL query parameters |
| Typosquatting | HIGH | Package name closely resembles a trusted popular package |
| Supply Chain Risk | MEDIUM | Low-trust package with no history, stars, or maintainers |
| PII Exposure | HIGH | Server handles sensitive personal data without proper controls |
| Outdated Package | CRITICAL | Package has known vulnerabilities in the installed version |
| Overly Broad Permissions | HIGH | Server requests filesystem or shell access it does not need |
| Telemetry Tracking | MEDIUM | Server contacts known analytics or tracking domains |
| Privacy Gaps | MEDIUM | Missing data retention, deletion, or encryption-at-rest policies |
| Unverified Source | MEDIUM | Package not from a verified registry or organization, and not published with npm provenance |
| Data Minimization | LOW | Tool requests significantly more data fields than necessary |
| Missing Transport | HIGH | MCP server communicates over unencrypted transport |

---

## Supported AI Tools

mcp-scan automatically detects configurations for **17 AI tool clients**:

| Category | Tools |
|----------|-------|
| **AI Assistants** | Claude Desktop, Claude Code, Gemini CLI, Codex CLI |
| **Editors** | VS Code, Cursor, Windsurf, Zed |
| **AI Coding Tools** | Cline, Roo Code, Continue.dev, Amp, Plandex |
| **Other** | ChatGPT Desktop, GitHub Copilot, Kiro, Warp |

---

## v2.0 Features

- **Data Flow Analysis**: Trace where your data goes after MCP processes it
- **Network Egress Monitor**: See every endpoint your servers contact
- **Privacy Assessment**: One-command PII and compliance report
- **Policy Engine**: Custom security rules in `.mcp-scan-policy.yml`
- **Compliance Mapping**: SOC 2, GDPR, HIPAA, PCI-DSS, NIST 800-53
- **SBOM Generation**: CycloneDX and SPDX output
- **CI/CD Integration**: Scan on every PR with SARIF output for GitHub, GitLab, and most security tools
- **16 scanners**: Secrets, supply chain, prompt injection, data flow, and more

---

## All Commands

```bash
# Full security scan (auto-detects all AI tool configs)
npx mcp-scan@latest

# Output as JSON for CI/CD pipelines
npx mcp-scan@latest --json

# Privacy impact assessment and data map
npx mcp-scan@latest privacy

# Compliance report (SOC 2, GDPR, HIPAA, PCI-DSS, NIST 800-53)
npx mcp-scan@latest compliance

# Software Bill of Materials (CycloneDX or SPDX)
npx mcp-scan@latest sbom

# Validate custom security policies
npx mcp-scan@latest policy validate

# CI mode: exit 1 on CRITICAL or HIGH findings (plain scans report without failing)
npx mcp-scan@latest --ci --severity high
```

---

## CI/CD Integration

Add mcp-scan to any CI pipeline via `npx`. Emits SARIF 2.1.0 which GitHub, GitLab, and most security tools pick up:

```yaml
# GitHub Actions example
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: 20
  - run: npx mcp-scan@latest --sarif mcp-scan.sarif --severity medium
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: mcp-scan.sarif
```

GitLab CI, CircleCI, or any runner works. `npx mcp-scan` is the portable entrypoint.

---

## Custom Security Policies

Define your own rules in `.mcp-scan-policy.yml`:

```yaml
version: 1
rules:
  - id: block-external-secrets
    description: Block any server that leaks secrets to unknown endpoints
    action: block
    match:
      finding_id: ["exposed-secret", "exfiltration-vector"]

  - id: escalate-supply-chain
    description: Treat low-trust packages as critical
    action: override-severity
    severity: critical
    match:
      finding_id: supply-chain-low-trust

  - id: allow-local-network
    description: Skip unknown-endpoint findings for local development
    action: skip
    match:
      finding_id: network-egress-unknown
      category: ["localhost", "127.0.0.1"]

  - id: warn-on-pii
    description: Flag any server that handles card data
    action: warn
    match:
      severity: critical
      pii_types: ["Credit Card"]
```

Rules need `id` + `action` (`block`, `warn`, `skip`, `override-severity`).
Match keys: `server_name`, `finding_id`, `severity`, `category`, `license_type`, `pii_types`.
Validate with `mcp-scan policy validate`.

---

## Compliance Mapping

| Framework | Controls Covered |
|-----------|-----------------|
| SOC 2 | CC6.1, CC6.6, CC6.7, CC7.1 |
| GDPR | Art. 25, Art. 32, Art. 33 |
| HIPAA | 164.312(a)(1), 164.312(e)(1) |
| PCI-DSS | Req. 6, Req. 10, Req. 11 |
| NIST 800-53 | CA-7, RA-5, SA-11, SI-2 |

---

## Privacy & Security Architecture

mcp-scan runs locally on your machine. Config parsing, regex scanning, and all heuristics happen in-process. The only network calls are optional supply-chain lookups (npm registry, OSV.dev for CVEs, GitHub API for trust scoring), which can be disabled with `--offline`.

- Local config parsing and analysis only
- No API keys required
- No telemetry, no account, no sign-up
- Optional npm/OSV.dev/GitHub API lookups for supply-chain and CVE scanning, off with `--offline`
- Fully open source. Audit the code yourself.

---

## Roadmap

- **v2.1**: Runtime Monitoring (proxy that inspects live MCP traffic)
- **v2.2**: Sandboxed Execution for scanned servers
- **v2.3**: Real-Time Alerting

## Read

- [The State of MCP Security](https://thynkq.com/writing/state-of-mcp-security-2026-08): ecosystem size, real scan data from a workstation and the official registry, and the incidents behind the headlines.

---

## Installation

Use without installing (always latest version):

```bash
npx mcp-scan@latest
```

Install globally:

```bash
npm install -g mcp-scan
mcp-scan
```

Install on macOS via Homebrew:

```bash
brew tap Abanoub-Rodolf/mcp-scan
brew install mcp-scan
```

---

## Paid next steps

`mcp-scan` itself is free and MIT. When a scan finds something that needs a
decision, two paid options exist — neither is required to use the scanner:

- **MCP Risk Review** — a human-led, 48-hour review of a real MCP setup by the
  maintainer, with a clear go / fix / escalate recommendation. See
  [thynkq.com/pricing#specialist-review](https://thynkq.com/pricing#specialist-review).
- **mcp-scan Pro waitlist** — hosted reports, policy packs, and buyer-safe risk
  summaries for teams that need a shareable artifact after a local scan. Join at
  [thynkq.com/products/mcp-scan#mcp-pro-waitlist](https://thynkq.com/products/mcp-scan#mcp-pro-waitlist).

---

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

For security disclosures: see [SECURITY.md](SECURITY.md).

---

## License

MIT. Built by [Abanoub Rodolf Boctor](https://thynkq.com/about) · [ThynkQ](https://thynkq.com)
