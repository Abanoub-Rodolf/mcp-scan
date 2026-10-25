# Changelog

All notable changes to mcp-scan are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [2.3.0] - 2026-10-25

### Added
- `custom-registry` finding: an `npx` or `npm exec` server that installs from a registry other than the npm registry (`--registry` or any prefix npm accepts such as `--reg`, `--@scope:registry`, or `npm_config_registry` / `npm_config_@scope:registry` in the server's env, any key case) is now flagged, HIGH for plain http, MEDIUM otherwise. A `--userconfig` or `--globalconfig` flag (or its `npm_config_` env) is flagged MEDIUM too, since that file can set the registry, and `--prefix` LOW, since it moves the global npmrc. For `npx`, a `--registry` after the package belongs to the server and is ignored; a value after any other npx flag is read as that flag's, so it doesn't hide a later `--registry`. `npx.cmd` and path forms count. Before, `npx --registry=https://npm.evil.example -y @modelcontextprotocol/server-filesystem` was reported as an official server. A custom registry for the package (unscoped, or its own scope) now also skips the name allowlists and the npmjs provenance lookup, since both describe the npm registry's copy, not the one that runs. Known-malicious names are still blocked.

### Fixed
- `npx.cmd`, `NPX.CMD`, `npm.cmd` and full-path launchers (`/usr/local/bin/npx`, `C:\nodejs\npm.cmd`) now get the typosquat, supply-chain, CVE and package checks, the candidate expansion and the `blockedPackages` policy. Only the registry check matched them before, so a blocked package launched as `NPX.CMD` was not blocked. Extra package candidates are graded with the launch's registry flags and env.
- `npm exec <pkg>` and `npm x <pkg>` are graded on the package, not on `exec`/`x`, also with npm flags before the subcommand (`npm --yes exec <pkg>`), and npx options that take a value (`--registry`, `--cache`, `--userconfig`, `--prefix`, `-w`/`--workspace`, `--loglevel`, `--before`, `--otp`, `--tag`, `--node-options`, `--script-shell`, `--shell`, `--proxy`, `--https-proxy`, `--cafile`, `--include`, `-C`, `--globalconfig`, `--omit`, `--fetch-timeout`, `--fetch-retries`, `--@scope:registry`) no longer have that value graded as the package. The `-c`/`--call` command string is never treated as a package: it is graded as a command (shell and exfiltration checks) and no longer sent to the npm registry or the package, typosquat and supply-chain checks. A `-p`/`--package` beside it is still graded. An unrecognized flag no longer hides the package: when a flag might take a value, up to four leading positionals are candidates, the riskiest feeds the package checks, and `scan` runs the registry and typosquat checks (and the blocked-package policy) on every candidate. `--` ends options, `npm exe`/`npm innit` and other abbreviations of exec and init are understood, and `npm.cmd`/path forms count as npm. `npm exec` reads `--package` after the bin like npm does, every `--package` is graded, `-n` is read as taking a value, `npm cr`/`ini` (prefixes of create/init) map to `create-<pkg>`, and the blocked-package policy matches versioned specs (`pkg@1.2.3`). `--no-package` counts as `--package`, `-n` is treated as ambiguous (both neighbours graded), and `--package` values are ordered risky-first before a cap of 32. A `--package` after an unknown flag is still read, and `scan` runs the package and supply-chain checks on every candidate, not just the registry and typosquat ones. More value options are recognized (`--scope`, `--install-strategy`, `--ca`, `--cert`, `--key`, `--cpu`, `--os`, `--libc`, `--noproxy`, `--user-agent` and others). `npm init|create <pkg>` is graded as `create-<pkg>` (`@scope` as `@scope/create`), and other npm subcommands (`install`, `run`, ...) are no longer graded as a package. The post-scan report hint uses the same parse. Both sent the wrong name to the known-malicious, typosquat, CVE, registry and supply-chain checks.
- After an unknown npx flag, a `--package` found later no longer hides the positional packages: both are graded, as real npx runs the first positional. Path-like positionals are not looked up; git and URL specs still are.
- `HTTP://`, `Http://` and `WS://` URLs (any case) are reported by `http-transport-no-auth` and `insecure-transport`, and `fix` upgrades them. Schemes are case-insensitive, but the checks only matched lowercase, so these got no finding at all. The network-egress scanner and `submit` read schemes in any case too.

## [2.2.0] - 2026-10-25

Upgrade note: CI runs may start failing. A policy or custom rule file that is broken, or a YAML policy using `match.pii_types`, now stops the scan with exit 1 instead of being skipped. Fix or remove the file.

### Changed
- Policy loading now fails closed. If `.mcp-scan.json` or `.mcp-scan-policy.yml` (current directory, then home) exists but cannot be read or parsed, or has a wrong-typed field (`blockedPackages: "x"`, `maxSeverity: "severe"`, `privacy.maskPii: "true"`, a YAML policy without `version: 1` and a `rules` list, an empty YAML file), the command stops before scanning with an error on stderr naming the file and the problem, and exits 1. `--policy <path>` naming a file that does not exist does the same. It used to warn (or say nothing) and scan with no policy, which silently dropped `blockedPackages`, `requiredEnvVarPrefix`, `suppressRules`, `maxSeverity` and every YAML rule. A CI run that was passing with a broken policy file will now fail until the file is fixed or removed. Absent policy files are unchanged. Library callers of `runScan` get a thrown `PolicyError`, exported from the package; `watch` exits 1 on a bad policy at start, skips (never reports "all clear" for) a scan after the file breaks, and rescans when the fixed policy file is saved; `report` stops instead of skipping each config. `policy show` and `policy list` on a broken file (a dangling symlink included) now exit 1.
- A YAML policy is now checked beyond `id` and `action`: an unknown `match` key (`finding_ids`), a `match` value that is not a string or list of strings, or a severity that is not one of info, low, medium, high, critical (in an `override-severity` rule, any rule's `severity`, or `match.severity`) stops the run. Before, such a rule silently never matched, or wrote a severity the summary dropped, so `ci` could exit 0 with findings present.
- A custom rule file in `~/.mcp-scan/rules` that cannot be read, is not valid JSON, or holds an invalid rule (unknown `severity` or `target`, a `pattern` that is not a valid regex, wrong-typed `negate`) now stops the run instead of warning and scanning with the remaining rules. A missing rules directory is still fine.
- YAML policy `match.license_type` now works: it matches findings on servers whose package license equals the value (case-insensitive, exact). It was accepted before but ignored, so a `skip` rule using it matched every finding. `match.pii_types` is removed from the accepted keys because findings carry no PII field to match on, so a policy using it now fails to load; use `category` (a substring of the finding text) instead. The README example is updated.
- Custom rule files are read through the same non-blocking path as policy files, so a FIFO in `~/.mcp-scan/rules` is rejected instead of hanging the scan. A custom rule `severity` such as `constructor` is no longer accepted by accident.
- A policy path that is a dangling symlink reports the missing link target.
- A policy file behind a directory mcp-scan cannot search is treated as present and unreadable, not absent.
- A package whose registry entry has a legacy object license (`"license": {"type": "MIT"}`) or another non-string shape no longer crashes the scan; the license is stored as a string (the object's `type`, or the first `licenses[].type`) or left unset.
- YAML policy rules are stricter: an unknown top-level rule key (`matcher`, `scaner`), an empty or whitespace-only `scanner`, and empty strings in `match` values (alone or in a list) are errors. Before, they were ignored and the rule matched every finding.
- The policy file is opened once and its type checked on the open file, so a FIFO swapped in after the check can no longer hang the read.
- `runScan` (the library entry) now rejects with `BaselineKeyError` when `baseline.key` is a directory or any other non-regular file, before it does any work. The class is exported from the package root so callers can `instanceof` it; the CLI already turns it into a one-line error and exit 1.
- Test lint (`local/no-sleep-promise`) closes more ways to write a fixed sleep: a resolver passed as a later timer argument (`setTimeout(go, 5, r)`, spread included), `r.call(...)` and `r.apply(...)` in a timer callback, a named executor (`new Promise(exec)`), a defaulted resolver parameter (`(r = noop) => ...`), `Promise.withResolvers()` resolved only by a timer, a const alias of the timer (`const t = setTimeout`, `const { setTimeout: t } = globalThis`), and any import of `node:timers` or `timers`, including `import()`, `require()`, template-literal and `getBuiltinModule` forms. The whole `timers` module is banned, not just `timers/promises`: nothing here needs it, and the global `setTimeout`, `setInterval` and `setImmediate` are the same functions without an import. Dev tooling only; nothing in the shipped package changes.

### Fixed
- A Claude or Codex plugin manifest whose `mcpServers` is a path (`"./.mcp.json"`) or a list of paths is now followed to that file, relative to the plugin root. It used to be iterated by character, producing servers named `0`..`10` and a `duplicate-server` finding for each. References are followed one level, only inside the plugin root (symlinks resolved), and only to regular files; anything else is skipped with a warning on stderr, also under `--json` and `--ci`. Non-object server entries are skipped; an array of server objects is still scanned as before.
- `report` without `--json` prints its findings again. The per-file scans left the logger silenced, so the human report showed only the "Aggregating" and "Found N" lines.
- `report --json` writes only the JSON report to stdout. The "Aggregating reports from" and "Found N potential config files" lines now go to stderr.
- `${CLAUDE_PLUGIN_ROOT}`, which Claude Code expands for plugin servers, no longer triggers `high-entropy-value`, `env-var-scope-leak`, `shell-injection-risk`, `missing-env-var` or `missing-referenced-env-var`, in either `${VAR}` or bare `$VAR` form. Command substitution or `;`, `|`, `&` or a newline after it, and a high-entropy value appended to it, are still reported.
- `npx --package=<pkg> <bin>` (also `--package <pkg>`, `-p <pkg>` and `-p=<pkg>`) is graded on the package, not the bin, by `unverified-source`, typosquat, supply-chain and package checks. With several packages, the first one not on an allowlist is graded, so an official package cannot hide an unknown one. Only options before the first positional count: a `-p 8080` after the package is the server's.
- `http-transport-no-auth` on a loopback URL (`http://localhost`, `127.x.x.x`, `[::1]`) is LOW instead of HIGH and is not auto-fixed to https. A loopback URL in args is LOW and not auto-fixed either.
- The `server-mutation` baseline is keyed per config file. Two files defining the same server name no longer report each other as an unauthorized change in one clean scan. Entries from older stores are checked once, on the first scan after upgrading, against every file with that name, so a monorepo may see one last `server-mutation` then.
- A scan that cannot append to `~/.mcp-scan/audit.log` (full disk, read-only home, a directory in the way) now prints one line to stderr naming the log and the error. It was silent, so a missing audit trail went unnoticed. The scan still completes.
- The offline CVE lookup warns on stderr when it fails on an unexpected snapshot shape ("vulnerability results may be incomplete"), including under `--json` and `--ci`, and from commands that print no scan report, such as `sbom`. It used to return no findings, which read as "no known vulnerabilities". The warning is on stderr only; stdout matches a healthy snapshot's (for `scan --json`, apart from the two scan-duration fields, which differ between any two runs).
- Every failed `doctor` check prints its reason without `--verbose` (for the npm update check: registry unreachable, or the HTTP status) instead of a bare failure.
- `proxy`: when the server closes its stdin but keeps running, a request whose write to it fails now gets a JSON-RPC error reply. Before, a client that sent several requests in one write after that point (or the single request that first hit the broken pipe) never heard back and waited forever; only requests arriving after the broken pipe was noticed were answered. Not covered: a request the operating system's pipe had already accepted before the server closed its stdin. The write succeeded, so the proxy cannot tell it was never read, and it still gets no reply.
- `watch` now rescans when `baseline.key` is fixed. It used to watch only config and policy files, so after a `BaselineKeyError` recovery waited on an unrelated config edit. The error is now followed by a dim "Scan skipped. Fixing baseline.key rescans." line, like the policy error. If the `~/.mcp-scan` directory does not exist yet, it is simply not watched.
- Every scan left a new `known-servers.json.backup-<timestamp>` in
  `~/.mcp-scan` and nothing removed them; one real install had over 1,100.
  Scans now keep the 5 newest. Backups the `fix` command makes of your own
  MCP client configs are never pruned.
- If `baseline.key` is a directory (or any other non-file, such as a FIFO), mcp-scan now stops before scanning with a one-line error naming the path and exits 1. Before, every scan printed a misleading "fingerprint store went missing" MEDIUM for each server, never signed a baseline and exited 0; a FIFO there hung the scan. Move or remove the path and rerun.
- A `.mcp-scan-ignore` that is a FIFO no longer hangs the scan forever. Any non-regular file there (FIFO, directory, device) is skipped with a line on stderr, so no suppressions apply. Skipping can only add findings, never hide one.
- When the proxy gives up on a client that stopped reading, the "dropped N bytes of queued output" warning now counts writes queued behind the one in flight. It used to report only the unsent part of the first write (about 30 MB instead of about 35 MB in a measured case). The warning text is the only thing that changes.

## [2.1.0] - 2026-10-09

### Security
- The known-servers baseline is signed (HMAC-SHA256, per-install key in `baseline.key`, mode 0600). A hand-edited store, a stripped signature or a damaged key is reported as tampering (MEDIUM) and the store is set aside and rebuilt. A missing key counts as tampering only when the store was signed or the audit log shows an earlier signing; otherwise it reads as an upgrade.
- A deleted baseline is reported as a missing baseline (MEDIUM) when the key or the audit log still shows an earlier one, instead of being treated as a quiet first run. Deleting the baseline, the key and the audit log together still reads as a first run; that is a local-store limit, described in the README.
- An unreadable, corrupt or unknown-schema baseline now fails closed with a MEDIUM `server-mutation` finding instead of being silently trusted.
- A change in the registry's latest version for a server whose spec names no version (or `@latest`), patch releases included, is reported at MEDIUM. Only live registry values are compared; the bundled offline snapshot never is, so going offline or upgrading mcp-scan is not a change. Any other spec (`pkg@x.y.z`, a range, a tag) is covered by the config fingerprint instead.
- Proxy logs are created 0600 in a 0700 directory, and lines that fail to parse or mask are no longer written to the log. A message the privacy engine could not mask is dropped without leaving the other side hanging: a dropped request gets a JSON-RPC internal error (-32603) back to its sender, a dropped response is replaced by an error for the same id, and a dropped notification warns on stderr.
- With `privacy.maskPii` on, every string value, every object key except the six JSON-RPC envelope keys `jsonrpc`, `id`, `method`, `params`, `result` and `error` (colliding masked keys are suffixed `_2`, `_3`, none dropped) and every non-JSON line that ends in a newline, in both directions, goes through the built-in detectors before it is logged or forwarded. A final line with no trailing newline is masked and logged like any other if it is JSON (it used to be forwarded raw); if it is not valid JSON it is dropped with a warning.
- Masking fails closed: a message nested past 100 levels, or that errors while being masked, is dropped and answered with a -32603 error carrying the sender's original id (it used to be forwarded and logged unmasked past 100 levels). Not covered: non-string JSON values such as numbers, text the detectors do not match, and the server's own stderr, which passes through untouched.
- A server that closes its stdin (EPIPE) no longer crashes the proxy. It warns once per stream (stderr, or the dashboard under `--ui`), and every request that arrives after the error is seen gets a -32603 error carrying its own id; notifications are ignored. A request already in flight when the error surfaces gets no reply.
- If the client goes away (the proxy's stdout closes), the proxy terminates the server and exits instead of leaving both running.
- After the server exits, the proxy waits for its output pipe to close. If a process the server started keeps that pipe open, it exits once output has been idle for 2 seconds (nothing arriving from the server and nothing queued for the client). A client that has output queued and takes no bytes of it for 60 seconds (progress is counted in bytes the pipe accepts, so a slow reader of even one huge line never trips it) is given up on, and the proxy exits at most about a second after that. Output already queued on the proxy's stdout at that point is lost, with a warning; server output the proxy had not processed yet is dropped, also with a warning (stderr, or the dashboard under `--ui`). When the server exits, a last line cut off mid-message is kept if it is complete JSON and otherwise dropped with a warning, so a fragment is never forwarded as a message. The proxy log is closed only after every line the proxy forwards, an unterminated last one included, has been masked and written.
- The proxy refuses to start (exit code 1, no server launched) if `.mcp-scan.json` exists but cannot be parsed or is not a JSON object, instead of running with masking silently off.
- The `id` of a top-level JSON-RPC message (an object with `"jsonrpc": "2.0"` and one of `method`, `result` or `error`; each element's, in a batch) is passed through unmasked and unrenamed, by design: it is a correlation token, and masking `req-1234567890` or a UUID would stop replies matching their requests. A dropped message is answered with that same raw id. The same text inside params or a result is still masked. An id that itself looks like PII therefore appears in the proxy log as sent.
- With masking off, the proxy forwards each JSON line as received (it used to re-serialize it) and no longer throws on extremely deep nesting.
- Masking compiles its detectors once instead of per string: a 1.9 MB, 20,000-object response masks in about 46 ms instead of about 160 ms.
- The proxy decodes UTF-8 across chunk boundaries, so multibyte text in long lines no longer turns into U+FFFD, and it waits for the server's last output to drain before exiting.
- `npx pkg@latest` (and `@scope/pkg@latest`) is now looked up in the registry by its bare name, so the latest-version change check actually runs for it.
- smol-toml 1.9.1 and lodash 4.18.1 clear known advisories.

### Changed
- Do not run mcp-scan 2.0.13 or older against a store that 2.1.0 has signed (for example a global 2.0.13 next to an `npx mcp-scan@latest`). The old version loads the whole store, overwrites its own entries with old-recipe fingerprints and writes it back without re-signing, so the next 2.1.0 scan reports a MEDIUM integrity failure ("signature does not match") for every server. It is a one-time false alarm: that scan sets the file aside as `known-servers.json.corrupt-<time>` and rebuilds a signed baseline, and the following scan is clean. Use one version per machine, or review the configs by hand after the alarm.
- The fingerprint covers the config you wrote plus the package name; the resolved version is tracked separately.
- Upgrading from 2.0.x resets the baseline once: that scan reports one INFO per scanned server ("baseline was reset") and makes no change check, then writes a signed baseline. A current-format store that is only unsigned is compared as usual and signed with a single INFO line. The empty `{}` store that 2.0.13 writes after a scan with no servers is treated like any other 2.0.x store: one INFO per scanned server, then a signed baseline. It is reported as tampering (MEDIUM) if this install signed a baseline before or a key is already present.
- The stale CVE snapshot warning prints once per run.
- `mcp-scan proxy` sends all its own log lines (banner, info, warnings) to stderr, so stdout carries only the MCP protocol. Scan output is unchanged.

### Build
- Publishing to npm now requires build, tests, lint and a dependency audit gate to pass.
- `npm test` builds first, so a fresh clone goes green.
- Internal planning and campaign notes are no longer tracked in the repo.

## [2.0.13] - 2026-09-07

### Changed
- Terminal output shows config paths under your home directory as `~`
  instead of the full path. JSON, SARIF, HTML, and audit-log output are
  unaffected, still absolute.
- Fixed the header box border misaligning in most terminals (a double-width
  emoji threw off the padding math).

### Added
- A one-line, once-per-machine hint after a scan finds something: mcp-scan
  is maintained by one person, a star helps others find it. Only prints on
  a real terminal, never under `--json`, `--sarif`, CI, or piped output.
  Silence it permanently with `MCP_SCAN_NO_HINTS=1`.

## [2.0.12] - 2026-09-05

### Changed
- Registry scanner checks npm provenance attestations before flagging a package as
  unverified. A package published with `npm publish --provenance` now gets an INFO
  `provenance-verified` finding instead of `unverified-source`. Packages without
  provenance still get `unverified-source`, now at MEDIUM (unscoped) or LOW (scoped)
  instead of HIGH/MEDIUM, since name-based unverified checks alone were flagging
  most of npm, including mcp-scan's own package.
- `blessed` and `blessed-contrib` (the TUI dashboard's terminal-rendering
  libraries) moved from `dependencies` to `optionalDependencies`. They're
  still installed by default for `npx`/CLI users, but `import { runScan }
  from 'mcp-scan'` no longer pulls in 2MB of terminal-UI packages (and
  their `xml2js` transitive) for consumers who never touch the dashboard.
  `mcp-scan dashboard` and `proxy --ui` now print an install hint and exit
  1 instead of crashing if the optional install was skipped.

### Added
- `mcp-scan badge <package>` prints the README badge markdown and report link
  for a package's hosted check at thynkq.com; `scan` now ends with the same
  report hint for the scanned package.

### Fixed
- npm provenance publishing works again: `repository.url` must name the GitHub
  repo the release workflow runs in, or the registry rejects the sigstore
  bundle (the 2.0.11 tag never reached npm for this reason).

## [2.0.11] - 2026-09-05

### Fixed
- data-controls: config file paths no longer scanned for PII.

## [2.0.10] - 2026-09-01

### Added
- A one-line pointer to the GitHub repo after a `scan` that finds at least one
  issue. Shown once per machine ever (marker in `~/.mcp-scan`), TTY-only,
  never in `--json`, `--sarif`, or `ci` output, silenced permanently with
  `MCP_SCAN_NO_HINTS=1`.

## [2.0.9] - 2026-09-01

### Fixed
- `report` no longer drops dotfile configs from its glob scan. fast-glob excludes
  dotfiles by default, which silently skipped `.mcp.json`, the single most common
  MCP config filename. The command could report "found N config files" while
  scanning none of the servers those configs defined.
- Licenses are no longer reported missing when the registry lookup falls back to
  offline mode.
- Placeholder credentials in example configs are no longer flagged CRITICAL.
- Vulnerability matching compares the resolved version against the advisory range
  instead of matching on package name alone.

## [2.0.8] - 2026-08-29

### Added
- The scan footer now links the rules reference at thynkq.com/docs/mcp-scan/rules
  when findings exist. Every rule id has a page there: what triggers it, when it
  is a false positive, and how to fix it, the same URLs SARIF `helpUri` has
  always carried, live for the first time.

## [2.0.7] - 2026-08-29

### Added
- A one-line pointer to the hosted report option after high-intent commands
  (`compliance`, `sbom`, `policy show`, and a failed `ci` gate, on stderr).
  TTY-only, never in JSON or SARIF output, silenced permanently with
  `MCP_SCAN_NO_HINTS=1`. The scanner itself stays free and unchanged.

## [2.0.6] - 2026-08-23

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
