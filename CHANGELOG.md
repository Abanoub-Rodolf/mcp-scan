# Changelog

All notable changes to mcp-scan are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security
- Dependency audit: bumped undici (7 high advisories), uuid, and vite
  (2 high advisories) past their patched versions; rebuilt the GitHub
  Actions bundle with them inline.
- Accepted residual risks, upstream-blocked: lodash high via
  `blessed-contrib` (affects only the interactive dashboard TUI, no
  patched upstream exists yet) and esbuild low (dev-only, Windows dev
  server). Revisit when upstream releases land.

## [2.0.5] - 2026-08-23

### Fixed
- `ci --max-severity` now fails on LOW and INFO findings as documented;
  previously the flag silently ignored both severities.
- CLI severity colors: HIGH was rendered in critical red and MEDIUM in
  high orange. All surfaces (CLI, HTML, dashboard, spinner) now share one
  palette.
- An INFO-only scan printed "All clear" in the terminal while HTML and
  Slack reported "N findings detected". The all-clear check now counts
  every severity everywhere.
- Slack webhook: a rejected fetch leaked the 10s abort timer; transport
  is now unified with an always-cleared timeout helper.
- `mcp-scan fix`: url-based `http-transport-no-auth` and `insecure-transport`
  servers were detected but never remediated; both are fixed now. Servers
  carrying an insecure scheme in args AND url get both rewritten.
- LOW findings render green (the shared palette) in HTML and terminal
  badges instead of gray; the terminal summary row keeps its dim styling.
- Library note: `ScanOptions.fix` was removed from the public type. The
  interactive fix flow is CLI-only (`mcp-scan fix` / `--fix`); passing it
  to `runScan` had become a silent no-op, which is now a visible compile
  error for TypeScript consumers.
- With `MCP_SCAN_HOME` set, custom rules now load from that home; a
  warning points at legacy rules left in `~/.mcp-scan/rules`.
- SBOM: CycloneDX component purls are built by one function so
  vulnerability `affects[].ref` joins cannot silently break; corrected a
  wrong repository URL.
- Two type errors that made plain `tsc --noEmit` fail (invisible to tsup
  builds) are fixed.

### Changed
- Finding ids live in one list: the `FindingId` union is derived from it,
  replacing a hand-maintained duplicate that had already drifted.
- Severity tallying is shared by scan/report/audit/submit instead of five
  divergent inline chains (scan also tallied twice per run).
- fetch timeout handling unified across package scanner, doctor, submit,
  and webhooks; offline CVE snapshot read through one loader that warns on
  parse failures instead of failing silently.
- Custom rules directory honors `MCP_SCAN_HOME` at call time (previously
  frozen to the real home dir at module load); rule file read failures are
  no longer misreported as parse failures.
- Tool config paths generated from one declarative table (adding a tool is
  one entry); proven byte-equivalent across 24 platform/home/env combos.
- Compliance command computes one assessment consumed by console, CSV,
  JSON, and Markdown renderers; outputs verified byte-identical.
- Config parsing boundary typed honestly (`RawMcpServerEntry`), removing
  `as any` casts in parser and fix paths.

### Added
- 26 new tests: real abort-path coverage for OSV.dev timeouts (the old test
  slept 4 real seconds without testing the timeout), unit coverage for the
  Levenshtein typosquatting math, scan-text surface builder, CI threshold
  matrix, and auto-fix strategies.

### Security
- No detection patterns or thresholds changed; every scanner emits exactly
  as before (verified by the full suite plus golden output diffs).

## [2.0.4] - 2026-08-15

### Added
- npm `funding` field: exposes the GitHub Sponsors link on the npm package
  page. Metadata-only release.

### Security
- Prompt-injection and tool-poisoning scanners now evaluate the full tool
  catalog: tool names, descriptions, and nested JSON schema description/
  enum values. The 2026 MCP threat model treats the catalog as part of
  the prompt, so payloads hide in schema fields, not just descriptions.
- SARIF output: rule table aligned with the ids scanners actually emit
  (dead `malicious-package`/`typosquatting-package`/etc. keys removed),
  `originalUriBaseIds` declared so `%SRCROOT%` resolves for GitHub code
  scanning, POSIX URI separators on Windows, dead account URL fixed.
- Compliance mappings aligned to emitted finding ids (`known-malicious`,
  `typosquat-detection`, `supply-chain-low-trust`, `server-mutation`, ...)
  so SOC 2 / GDPR / HIPAA / PCI-DSS / NIST controls actually match.

### Fixed
- Library API: `ScanOptions` is now a single source of truth shared by
  the CLI, `runScan`, and the public entry; HTML/SARIF/SBOM generators
  are exported from the library.
- Proxy `--args` parsing respects quotes and commas instead of naive
  split-on-space, so multi-word values work.
- GitHub Action runner moved from the deprecated `node20` to `node24`;
  pre-commit hook declares the npm dependency so the `mcp-scan` entry
  resolves.
- `audit` command uses exit codes instead of `process.exit`.

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
