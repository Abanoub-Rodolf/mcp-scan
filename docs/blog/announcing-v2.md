# mcp-scan 2.0.x: Security-Hardened, Provenance-Signed

mcp-scan is an open-source security scanner for Model Context Protocol (MCP) servers. It audits the configs of Claude Desktop, VS Code, Cursor, Windsurf, and 12 more AI clients for secrets, prompt injection, supply-chain risks, and 17 check classes. Everything runs locally: zero telemetry, no data leaves your machine.

This release family (2.0.3 + 2.0.4) is the result of a full end-to-end security audit of the scanner itself, plus a hardening pass on the distribution pipeline. The full audit record lives in [docs/AUDIT-2026-08-15.md](AUDIT-2026-08-15.md).

## Security fixes

- **Stored XSS closed** in HTML reports: server-controlled strings were interpolated unescaped. A malicious MCP server could inject script into a report opened in a browser.
- **Command injection closed** in `mcp-scan doctor`: the `which` check ran through a shell.
- **Proxy no longer logs raw unmasked traffic** to disk. Log directory is configurable via `MCP_SCAN_LOG_DIR`.
- **Secret scanner false positives eliminated**: UUIDs-as-CRITICAL-secrets (Pinecone/Heroku), bare 40/36/64-char "tokens", and non-string env crashes fixed; added `github_pat_`, `rk_live_`, `whsec_` formats.
- **PII cascade fixed**: Luhn-validated cards, private-IP exclusion, keyword-gated numeric shapes, and a `/g` lastIndex silent-detection bug.
- **CVE scanner keeps every known vuln**: CVSS v4 and plain numeric scores were silently dropped; the upgrade advisor recommended upgrades exactly when they fixed nothing. Snapshot rebuilt from live data (74 packages, real advisories).

## Threat model: the tool catalog is part of the prompt

The 2026 MCP threat model treats the tool catalog itself as part of the model's context. Tool names, descriptions, and nested JSON-schema `description`/`enum` values all enter context at `tools/list` time — which means injection payloads hide in schema fields, not just in `server.description`.

The prompt-injection and tool-poisoning scanners now recursively collect the entire `schema.tools` structure (keys included) instead of scanning only the server description and arg values. Regression tests prove payloads buried in a nested `inputSchema` description are caught by both scanners.

## Distribution

- npm publishing now runs entirely through **OIDC trusted publishing**: no tokens, no secrets, full provenance attestation on every release. `v2.0.4` is provenance-signed via GitHub Actions.
- The GitHub Action is standalone-bundled (it previously crashed with `Cannot find module semver`), runs on node 24, and uploads SARIF to the Security tab.
- Compliance mappings (SOC 2 / GDPR / HIPAA / PCI-DSS / NIST) and the SARIF rule table are now generated from the actual emitted finding IDs — no dead references, no drift.

## Numbers

- 246 tests passing across 40 test files
- 16 scanners, 19 CLI commands
- 5 compliance frameworks, 2 SBOM formats (CycloneDX, SPDX)
- 0 dead finding IDs in compliance/SARIF mappings
- Zero telemetry

## Try it

```bash
npx mcp-scan@latest
```

GitHub Action: `uses: Abanoub-Rodolf/mcp-scan@v2` (standalone-bundled). Source: [github.com/Abanoub-Rodolf/mcp-scan](https://github.com/Abanoub-Rodolf/mcp-scan). npm: [mcp-scan](https://www.npmjs.com/package/mcp-scan).
