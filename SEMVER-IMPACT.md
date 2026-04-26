# SEMVER-IMPACT.md

Tracks all public API exports and their semver classification. Updated when the public API changes.

Current version: 2.0.1
Branch: audit/v1 (pre-release quality pass)

---

## Public API Surface

Source: `dist/lib.d.ts`

### Exported Functions

| Symbol | Signature | Semver Risk |
|--------|-----------|-------------|
| `runScan` | `(options?: ScanOptions) => Promise<ScanReport>` | Breaking if signature narrows |
| `detectTools` | `(dependencies: DetectorDependencies) => Promise<DetectedTool[]>` | Breaking if signature narrows |

### Exported Types

| Symbol | Kind | Semver Risk |
|--------|------|-------------|
| `ScanOptions` | interface | Adding optional fields = minor. Removing fields = major. |
| `ScanReport` | interface | Adding optional fields = minor. Removing fields = major. |
| `ServerScanResult` | interface | Adding optional fields = minor. Removing fields = major. |
| `Finding` | interface | Adding optional fields = minor. Removing fields = major. |

### ScanOptions Fields (as of v2.0.1 + audit/v1 additions)

| Field | Type | Added | Notes |
|-------|------|-------|-------|
| `silent` | boolean? | v1.x | suppress output |
| `json` | boolean? | v1.x | JSON output mode |
| `verbose` | boolean? | v1.x | verbose output |
| `severity` | string? | v1.x | filter by severity level |
| `fix` | boolean? | v1.x | auto-fix mode |
| `config` | string? | v1.x | path to config file |
| `version` | string? | v1.x | version override |
| `ugig` | boolean? | v2.0 | ugig marketplace link |
| `ci` | boolean? | v2.0 | CI exit code mode |
| `sbom` | string? | v2.0 (audit/v1 fix) | SBOM output path (CycloneDX JSON) |
| `sarif` | string? | v2.0 (audit/v1 fix) | SARIF output path |
| `policy` | string? | v2.0 (audit/v1 fix) | policy file path |
| `offline` | boolean? | v2.0 (audit/v1 fix) | disable network calls |
| `submit` | boolean? | v2.0 (audit/v1 fix) | submit to ugig marketplace |

Note: `sbom`, `sarif`, `policy`, `offline`, `submit` were accepted by `runScan` internally but not declared in `ScanOptions`. This was a documentation gap, not a behavioral change. Fixed in audit/v1.

---

## Dependency Vulnerability Notes

### lodash (via blessed-contrib): HIGH severity, accepted residual risk

- Advisories: GHSA-r5fr-rjxr-66jc (`_.template` code injection), GHSA-f23m-r3pf-42rh (prototype pollution via `_.unset` and `_.omit`).
- Affected range: `lodash <=4.17.23`. The official lodash project released 4.17.21 as the last patched version in the 4.x line; later 4.17.x versions in npm are republishes outside the official maintainer chain.
- Resolved: package.json `overrides` pins `"lodash": "4.17.21"` (exact, official). `npm ls lodash` confirms 4.17.21 in the tree.
- mcp-scan usage: lodash is not called directly by mcp-scan. It is loaded transitively by blessed-contrib for the TUI dashboard feature only.
- Exploit path analysis: the cited advisories require attacker-controlled input to reach `_.template`, `_.unset`, or `_.omit`. mcp-scan passes no user input through any blessed-contrib code path; the dashboard renders read-only scan results from local config files.
- Decision: HIGH advisory accepted. `npm audit` is configured with `--audit-level=critical` so this does not break CI. `npm audit fix --force` would install `blessed-contrib@4.8.13` (a breaking change for the dashboard) and is deferred to a later phase.

### uuid: MODERATE severity, not exploitable in mcp-scan

- Advisory: GHSA-w5hq-g745-h8pq (missing buffer bounds check in v3/v5/v6 when `buf` argument is provided).
- Affected: `uuid@<14.0.0` (mcp-scan uses uuid@13.x).
- mcp-scan usage: only `uuidv4()` is called and `buf` is never passed. Vulnerability does not apply.
- Action: no upgrade needed. Documented here for tracking.

---

## CLI Public Interface (non-breaking guarantees)

The following CLI flags are stable and must not be removed or renamed without a major version bump:

- `scan` subcommand (default)
- `--json`, `--verbose`, `--severity`, `--fix`, `--config`, `--ci`
- `privacy`, `compliance`, `sbom`, `policy`, `fix`, `ls`, `audit`, `init` subcommands

The following flags were documented in README but do not exist and were removed from docs in audit/v1:
- `--severity-threshold` (never existed; Commander.js silently ignored it)
