# mcp-scan

[![npm version](https://badge.fury.io/js/mcp-scan.svg)](https://badge.fury.io/js/mcp-scan)
[![npm downloads](https://img.shields.io/npm/dw/mcp-scan)](https://www.npmjs.com/package/mcp-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/gitlab.com/abanoub.rodolf/mcp-scan/badge)](https://securityscorecards.dev/viewer/?uri=gitlab.com/abanoub.rodolf/mcp-scan)
[![npm provenance](https://img.shields.io/badge/npm%20provenance-signed-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)
[![mcp-scan](https://thynkq.com/api/mcp-scan/badge/mcp-scan.svg)](https://thynkq.com/mcp-scan/check/mcp-scan)

<p align="center"><img src="https://raw.githubusercontent.com/Abanoub-Rodolf/mcp-scan/main/assets/demo.gif" width="800" alt="mcp-scan auto-detecting two clients and reporting two critical findings"></p>

**Open-source security scanner for Model Context Protocol (MCP) servers.**

MCP servers run with full access to your filesystem, API keys, and network. mcp-scan audits every MCP server configuration on your system, detecting leaked secrets, prompt injection risks, supply-chain vulnerabilities, and data flow issues before they become incidents.

```bash
npx mcp-scan@latest
```

No installation. No sign-up. No telemetry. No data leaves your machine. Supply chain scanning makes registry lookups (npm, OSV.dev, GitHub API) - disable with `--offline`.

---

## Badge

Publish an MCP server yourself? Get a public badge for its README:

```bash
npx mcp-scan badge <your-npm-package-name>
```

Prints a ready-to-paste Markdown snippet linking to a hosted scan report at thynkq.com. The command itself makes no network calls and needs no account, but the badge image is served by thynkq.com and loads whenever someone views the README. Every scan also prints a public report link for each server it found, whether or not you publish it yourself.

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
| Unverified Source | MEDIUM (unscoped), LOW (scoped) | npm package from an unverified publisher, not published with npm provenance |
| Custom Registry | HIGH (http), MEDIUM (https) | Package installed from a registry other than the npm registry, so its name proves nothing |
| Data Minimization | LOW | Tool requests significantly more data fields than necessary |
| Missing Transport | HIGH | MCP server communicates over unencrypted transport |
| Live Tool Poisoning (`--live`) | HIGH | The tool, prompt or resource text a running server actually sends the model hides instructions, sensitive file paths, invisible Unicode or data side channels |
| Rug Pull (`--live`) | HIGH | A tool's definition changed since the baseline mcp-scan recorded |

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

## Enforcing proxy (`proxy --enforce`)

`mcp-scan proxy` sits between an AI client and a stdio MCP server. With `--enforce` it also decides which tool calls get through:

```bash
mcp-scan proxy --enforce --deny-tools 'delete_*,shell' -c npx -a '-y,@modelcontextprotocol/server-filesystem,/tmp/work'
mcp-scan proxy --enforce --allow-tools read_file,list_directory -c ...   # anything else is refused
mcp-scan verify-chain ~/.mcp-scan/proxy-chain.jsonl
```

A refused call never reaches the server; the client gets a JSON-RPC error (`-32001`, "Blocked by mcp-scan policy"). Every `tools/call`, allowed or refused, is appended to a log where each entry carries the hash of the one before it plus an HMAC under this install's baseline key. Editing or deleting an entry, or cutting off the end, makes `verify-chain` fail, and the proxy refuses to extend a log that does not verify. Arguments are not stored: only their key names and a keyed hash (HMAC) of the whole value, so the log can be shared with an auditor.

Limits: putting back an older, valid copy of both the log and its head file is not detected (keep a copy of the head somewhere the proxy cannot write); it filters by tool name on `tools/call`, not by what the arguments do; it does not see traffic that bypasses the proxy; and anyone who can read the baseline key can forge a chain, so keep `~/.mcp-scan` private.

---

## Live introspection (`--live`)

Config scanning reads what a server is *configured* to do. The tool-poisoning attack lives in what the server *says* once it runs: tool descriptions, parameter descriptions, prompts and resources are all read by the model. `--live` connects to each server over stdio or streamable HTTP, runs `initialize`, then pages through `tools/list`, `prompts/list`, `resources/list` and `resources/templates/list`, and checks every item on its own.

```bash
npx mcp-scan@latest --live
npx mcp-scan@latest --live --live-timeout 60000   # slow npx cold starts
npx mcp-scan@latest --live --accept-tool-changes   # I reviewed a change, make it the baseline
```

**This executes the server command from your config.** It is not a sandbox. Only run it on servers you would start anyway. The child gets a minimal environment (PATH, HOME, proxy and CA settings, plus the `env` from its own config entry), never the rest of your shell. It is killed with its whole process group when the scan ends, and its output, message count and paging are capped. Server requests back to the client (sampling, roots) are refused. `--offline` skips servers reached over a URL; stdio servers still start (and `npx` may fetch the package).

What it flags, always naming the tool, prompt or resource:

- fake `<IMPORTANT>` / `[SYSTEM]` markers and "do not tell the user" instructions
- instructions that point at SSH keys, cloud credentials or other tools' config
- a free-text parameter (`sidenote`, `context`, ...) described as taking file contents, history or keys: a data side channel
- invisible Unicode tag characters (decoded in the finding), zero-width and direction-control characters, and instructions pushed off-screen behind whitespace
- one tool rewriting how the model uses another tool, and the same tool name served by two servers
- instruction-override phrases, encoded blobs, and unreasonably long descriptions

**Rug pulls.** The first live scan records a SHA-256 per tool, prompt, resource and the server instructions in `tool-snapshots.json` (next to `known-servers.json`, signed with the same per-install key). Later scans report `tool-definition-changed` (HIGH for tools), `tool-added` and `tool-removed`, naming the field that moved. A changed definition keeps being reported until you run `--accept-tool-changes`, so a rug pull is not a one-scan event. A server that fails to connect produces a `live-unreachable` finding and never touches the baseline. An edited or deleted snapshot store is reported as `live-snapshot-tampered`.

Not covered yet: the legacy SSE transport, servers that need OAuth, and per-session or per-client tool lists (the baseline sees what this scan sees).

---

## All Commands

```bash
# Full security scan (auto-detects all AI tool configs)
npx mcp-scan@latest

# Output as JSON for CI/CD pipelines
npx mcp-scan@latest --json

# Live introspection: start each server, read its real tools/prompts/resources
# (tools/list etc.), flag poisoned descriptions, and detect rug pulls
npx mcp-scan@latest --live

# Privacy impact assessment and data map
npx mcp-scan@latest privacy

# Compliance report (SOC 2, GDPR, HIPAA, PCI-DSS, NIST 800-53)
npx mcp-scan@latest compliance

# Software Bill of Materials (CycloneDX or SPDX)
npx mcp-scan@latest sbom

# Public scan badge and report link for an npm package
npx mcp-scan@latest badge <package-name>

# Validate custom security policies
npx mcp-scan@latest policy validate

# CI mode: exit 1 on CRITICAL or HIGH findings (plain scans report without failing)
npx mcp-scan@latest --ci --severity high

# Interactive TUI dashboard (blessed/blessed-contrib install as optional
# dependencies; if the install was skipped, this prints an install hint)
npx mcp-scan@latest dashboard
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
      category: ["credit card"]
```

Rules need `id` + `action` (`block`, `warn`, `skip`, `override-severity`).
Match keys: `server_name`, `finding_id`, `severity`, `category` (substring of the finding text), `license_type` (the server's package license, exact match, case-insensitive). Any other key (in a rule or in `match`), an empty value, or a severity that isn't info, low, medium, high or critical, is an error.
Validate with `mcp-scan policy validate`.

A policy file that exists but can't be used stops the scan (error on stderr naming the file, exit 1) instead of running without it. That covers an unparseable `.mcp-scan.json` or `.mcp-scan-policy.yml`, a wrong-typed field (`"blockedPackages": "x"`), a YAML policy that fails `policy validate`, and `--policy <path>` pointing at a missing file. No policy file at all is fine; the scan runs with defaults.

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

### Tamper detection and its limits

mcp-scan fingerprints every server it scans and compares the next scan against that baseline (`~/.mcp-scan/known-servers.json`, or `$MCP_SCAN_HOME`). The baseline is signed so that an ordinary edit or removal is detected (the limits are listed below):

- The store carries an HMAC-SHA256 over its sorted contents. The key is 32 random bytes in `~/.mcp-scan/baseline.key`, created with mode 0600 on the first scan and never stored in the baseline.
- On an install that has a key or has signed before, a store with a missing or wrong signature, a signed store whose key is gone, or a damaged key is reported as `server-mutation` at MEDIUM for every server. The bad file is renamed to `known-servers.json.corrupt-<time>` and a new baseline is built. A missing or damaged key is replaced with a new one; a readable key is kept.
- A deleted store is reported at MEDIUM too when the key or the audit log shows an earlier baseline. A first run with neither stays quiet.
- A 2.0.x store (no schema marker) cannot be compared against the current fingerprint recipe, so the first scan after upgrading checks nothing for changes: it reports one INFO per scanned server ("baseline was reset"), then writes and signs a new baseline. A current-format store that is merely unsigned keeps its entries, is compared as usual, and is signed with a single INFO finding. Each scan records in `audit.log` whether it left a signed baseline, so an unsigned store on an install that signed before is reported as tampered, not as an upgrade.
- If you keep `~/.mcp-scan` in a CI cache, cache `baseline.key` with `known-servers.json`. A store restored without its key is reported as tampered.

What this does not stop: anyone running as your user can read `baseline.key`, so they can re-sign a forged store. They can also delete the key, the store and the audit log together and look like a first run, or rewrite the store without a signature, delete the key, and edit the audit log, which reads as the one-time upgrade and gets only an INFO. The audit log rotates at 10 MB, and a rotated log no longer vouches for earlier signing. It catches casual edits, scripts that rewrite the store, and deletion that leaves other traces. It does not defend against an attacker with full access to your account. For that, keep the baseline somewhere that account cannot write, or compare scan output in CI.

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
decision, two paid options exist. Neither is required to use the scanner:

- **MCP Risk Review**: a human-led, 48-hour review of a real MCP setup by the
  maintainer, with a clear go / fix / escalate recommendation. See
  [thynkq.com/pricing#specialist-review](https://thynkq.com/pricing#specialist-review).
- **mcp-scan Pro waitlist**: hosted reports, policy packs, and buyer-safe risk
  summaries for teams that need a shareable artifact after a local scan. Join at
  [thynkq.com/products/mcp-scan#mcp-pro-waitlist](https://thynkq.com/products/mcp-scan#mcp-pro-waitlist).

---

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

For security disclosures: see [SECURITY.md](SECURITY.md).

---

## License

MIT. Built by [Abanoub Rodolf Boctor](https://thynkq.com/about) · [ThynkQ](https://thynkq.com)
