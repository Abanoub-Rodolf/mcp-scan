# Changelog

All notable changes to mcp-scan are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [2.0.3] - 2026-08-15

### Security fixes (end-to-end audit)
- Stored XSS closed in HTML reports: every server-controlled string (tool descriptions, finding text, config paths) is now HTML-escaped.
- Command injection closed in `mcp-scan doctor`: `which`/`where` now run via `spawnSync` with an argument array instead of a shell string.
- Proxy no longer writes raw unmasked JSON-RPC payloads to disk: masking happens before logging, and the log dir honors `MCP_SCAN_LOG_DIR`.
- Secret scanner: prefix-less formats (Pinecone/Heroku UUIDs, Cloudflare/Railway/Together bare strings) are only reported when the env var key names the provider; added `github_pat_`, `rk_live_`, `whsec_` formats; non-string env values no longer crash scans; URL-decoded values are matched; `server.url` credentials are scanned.
- PII scanner: fixed the `/g` + `.test()` lastIndex bug that silently disabled PII detection from the second server on; credit cards require a Luhn-valid number; private/loopback IPs are excluded; bare 24-64 char "API key" detection removed; keyword terms are word-boundary and restricted to descriptive text.
- CVE scanner: OSV findings with CVSS v4 vectors or plain numeric scores are no longer silently dropped; upgrade advice was inverted and is fixed; offline snapshot severity mapping is exhaustive.
- `--ci` is the only mode that exits 1 on CRITICAL/HIGH findings; a plain interactive scan reports without failing the shell.
- Scanner failures are isolated per scanner (LOW `scanner-error` finding) instead of aborting the whole run.

### Fixed
- JSONC parser: state-machine comment/trailing-comma stripping no longer corrupts URLs containing `,}` or `//` inside strings.
- `fix` command preserves file permissions, symlinks, and keeps a timestamped backup instead of making 0600 files world-readable.
- `ci --output` works and `ci` forwards `--config`/`--policy`/`--offline`; `privacy --output` is now a real option; dead `sbom --include-deps` flag removed.
- `audit` deep-checks the audited server, not the first scanned one; `report` surfaces per-file failures instead of swallowing them.
- CVE snapshot regenerated from live OSV/npm data (74 packages, real advisories, no test fixture, fresh `updatedAt`).

### Added
- GitHub Actions CI matrix for Node 20/22 with job timeouts, an npm audit gate, and an npm publish workflow with provenance on version tags.
- Test suite is hermetic: scans redirect the audit store (`MCP_SCAN_HOME`) to a temp dir, CI tests run `--offline`, and a regression test covers the env-leak relative-path hang.

## [2.0.2] - 2026-04-27

### Fixed
- Hermetic, machine-portable golden-file tests (no absolute paths, no timestamps).
- Pinned `lodash` to 4.17.21 exactly; npm audit gate set to critical-only (blessed-contrib's transitive lodash advisories are documented as accepted residual risk in SEMVER-IMPACT.md).
- Include `data/` in GitLab CI build artifacts; drop Node 18 from the CI matrix (vitest 4 requires Node 20+).
- `.env.local`, `.env.production`, `.env.development`, `.env.staging` variants scanned by the env-leak scanner.
- Data-controls scanner: restored token-class API Key keywords.
- Library API: `sbom` option is a path string, not a boolean.
- Repository URLs pointed at the GitLab user namespace.

## [2.0.1] - 2026-03-28

### Changed
- Version bump for npm SEO metadata; v2.0 platform shipped as 2.0.x.

## [2.0.0] - 2026-03-28

### Added
- **Data Flow Analyzer**: traces data from sensitive sources (filesystem, clipboard, keychain, screen capture) to network sinks (HTTP, email/SMTP), with cross-server flow detection.
- **Network Egress Monitor**: flags suspicious endpoints, obfuscated URLs (base64/hex/reversed), raw IPs, non-standard ports, and telemetry/tracking domains; 8 additional AI provider endpoints, 8 tunneling endpoints, and 7 telemetry endpoints.
- **Privacy Assessment**: PII detection (email, phone, cards, SSN, IBAN, IPv4/IPv6, MAC, passport, driver license, NPI, VAT, AWS account), data minimization checks, and `mcp-scan privacy` reports.
- **Compliance Mapping**: SOC 2 (CC6.1, CC6.6, CC6.7, CC7.1, CC9.1, A1.1), GDPR (Art. 13, 25, 32, 33), HIPAA (164.308, 164.312), PCI-DSS (Req 6, 10, 11, 12), NIST 800-53 (CA-7, RA-5, SA-11, SI-2, RS.MI-1, PR.IP-1) with per-framework scores.
- **SARIF 2.1.0 output** for GitHub/GitLab code scanning, plus a GitHub Action (`Abanoub-Rodolf/mcp-scan`).
- **Policy Engine**: `.mcp-scan-policy.yml` rules (skip, block, warn, override-severity) and `.mcp-scan.json` project config.
- **SBOM generation**: CycloneDX v1.5 and SPDX 2.3 output.
- Scanner and data expansions: `/.etc`, `/var`, `/usr` dangerous paths; `.kube`, `.docker`, `.npmrc`, `.netrc`, ssh keys sensitive paths; bearer/cert/pem/keypair credential env patterns; IPv6/MAC PII masking; 13 additional trusted community servers; entropy-based secret detection; tool-poisoning and capability-injection scanner.
- `.env` file variants, offline mode with a bundled CVE snapshot, webhook/Slack alerting, `mcp-scan history`, `mcp-scan diff`, `mcp-scan doctor`, `mcp-scan report`, `mcp-scan audit`, watch mode with delta reporting, and a blessed TUI dashboard.

## [1.7.0] - 2026-03-24

### Added
- Interactive TUI dashboard command (`mcp-scan dashboard`) built with blessed-contrib.
- Local proxy server command (`mcp-scan proxy`) that intercepts MCP server traffic with PII masking and a privacy rule engine.
- Privacy engine with configurable PII masking rules and full test coverage.
- Self-contained HTML security report output (`--html report.html`).
- Tool Poisoning and Capability Injection scanner for MCP-specific attack classes.
- Entropy-based secret detection for high-entropy strings in env vars and args.
- CycloneDX v1.5 SBOM generation (`--sbom sbom.json`).
- Scan report diff command (`mcp-scan diff old.json new.json`).
- Webhook and Slack alerting integrations (`--webhook`, `--slack-webhook`).
- License compliance scanner (GPL, AGPL, LGPL, and unlicensed package detection).
- Cross-origin exfiltration analysis in AST scanner.
- Policy engine with `.mcp-scan.json` support for allowed/blocked packages and ignore rules.
- Persistent audit logging and scan history trends command (`mcp-scan history`).
- Offline mode with bundled CVE snapshot (`--offline`).
- Remediation confidence scoring and auto-apply logic in the fix command.
- Finding suppression via `.mcp-scan-ignore` file.
- Enhanced watch mode with delta reporting (webhook fires only on new findings).
- System diagnostic command (`mcp-scan doctor`).
- Multi-config report aggregation command (`mcp-scan report --configs dir/`).
- Server fingerprinting and mutation detection in the audit command.

### Fixed
- Build: copy `cve-snapshot.json` to `data/` directory on build.
- Missing `action.yml` output declarations for all finding count outputs.
- `detectTools()` dependency injection in `ls`, `watch`, and `audit` commands.

## [1.5.0] - 2026-03-24

### Added
- Community health files: CONTRIBUTING.md, SECURITY.md, CHANGELOG.md.
- Pre-commit hook configuration.
- GitHub Action with SARIF output for CI/CD integration.
- Public library API (`import { runScan } from 'mcp-scan'`), ESM and CJS dual output.

### Fixed
- `scanners` command crash in ESM builds (`__dirname` not defined). Replaced filesystem-based discovery with a static scanner list.
- Unified tsup build config with correct shims for ESM/CJS dual output.

### Changed
- Version 1.5.0: 10 scanners, 13 clients, SARIF, GitHub Action.

## [1.2.0] - 2026-03-24

### Added
- Prompt Injection scanner for malicious instructions in server descriptions and args.
- OSV.dev API integration for real-time package vulnerability lookups.
- Env leak scanner for detecting secrets in `.env` files within server directories.
- ugig.net MCP marketplace integration via `--submit` flag and `UGIG_API_KEY`.
- SARIF report output (`--sarif`).

## [1.1.0] - 2026-03-23

### Added
- 8 new AI tool config paths: Zed, Continue.dev, Cline, Roo Code, Amp, Plandex, ChatGPT Desktop, GitHub Copilot.
- Detection for project-level `.mcp.json` files.
- `--ci` flag for strict exit codes and JSON output in automated environments.
- Gemini CLI support.
- Codex CLI support with TOML parsing.
- Homoglyph and Levenshtein-based typosquatting detection.
- `--fix` flag for automated remediation of secrets and HTTP transports.
- Watch command improvement to monitor parent directories.

### Fixed
- Config deduplication: same config file detected by multiple tools no longer causes double reporting.
- Guard against undefined `command` in scanners.

## [1.0.0] - 2026-03-23

### Added
- Initial release.
- Core scanner pipeline: secrets, permissions, registry blocklist, typosquatting, transport security, and AST analysis.
- Config auto-detection for Claude Desktop, Cursor, VS Code, Claude Code, and Windsurf.
- JSON and TOML config parsing.
- Branded CLI output with severity-sorted findings and fix recommendations.
- Exit code 1 on critical or high findings for CI use.
