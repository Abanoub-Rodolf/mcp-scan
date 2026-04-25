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
| `sbom` | boolean? | v2.0 (audit/v1 fix) | SBOM generation |
| `sarif` | string? | v2.0 (audit/v1 fix) | SARIF output path |
| `policy` | string? | v2.0 (audit/v1 fix) | policy file path |
| `offline` | boolean? | v2.0 (audit/v1 fix) | disable network calls |
| `submit` | boolean? | v2.0 (audit/v1 fix) | submit to ugig marketplace |

Note: `sbom`, `sarif`, `policy`, `offline`, `submit` were accepted by `runScan` internally but not declared in `ScanOptions`. This was a documentation gap, not a behavioral change. Fixed in audit/v1.

---

## Dependency Vulnerability Notes

### lodash (via blessed-contrib) — HIGH severity

- Advisory: Prototype pollution in `_.template` and related functions
- Affected: `blessed-contrib@4.11.0` → `lodash@4.17.11`
- mcp-scan usage: lodash is not called directly by mcp-scan. It is used internally by blessed-contrib for the TUI dashboard feature only.
- Direct exposure: LOW — mcp-scan does not pass user-controlled input to lodash template functions
- Fix applied: Added `"overrides": { "lodash": ">=4.17.21" }` to package.json to force a patched lodash version
- Breaking upgrade alternative: `npm audit fix --force` installs `blessed-contrib@4.8.13` — deferred pending blessed-contrib breaking change review

### uuid — MODERATE severity

- Advisory: Buffer bounds check missing in v3/v5/v6 when `buf` argument is provided
- Affected: `uuid@<14.0.0` (mcp-scan uses uuid@13.x)
- mcp-scan usage: Only `uuidv4()` is called (no `buf` argument). Vulnerability does not apply.
- Action: No upgrade needed. Document here for tracking.

---

## CLI Public Interface (non-breaking guarantees)

The following CLI flags are stable and must not be removed or renamed without a major version bump:

- `scan` subcommand (default)
- `--json`, `--verbose`, `--severity`, `--fix`, `--config`, `--ci`
- `privacy`, `compliance`, `sbom`, `policy`, `fix`, `ls`, `audit`, `init` subcommands

The following flags were documented in README but do not exist and were removed from docs in audit/v1:
- `--severity-threshold` (never existed — Commander.js silently ignored it)
