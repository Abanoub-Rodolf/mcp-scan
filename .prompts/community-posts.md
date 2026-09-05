# mcp-scan Community Post Drafts

All drafts are ready to post manually. Do NOT post these automatically.

Current facts (v2.0.3, 2026-08-15): 17 AI tool clients, 16 scanners, 17 check
classes, 244 passing tests, GitHub public at gitlab.com/abanoub.rodolf/mcp-scan
npm `mcp-scan@2.0.2` (2.0.3 publish pending NPM_TOKEN), audit record in
docs/AUDIT-2026-08-15.md, awesome-list PR
https://github.com/punkpeye/awesome-mcp-servers/pull/12192.

---

## Hacker News (Show HN)

**Title:** Show HN: mcp-scan – security scanner for MCP server configurations

**URL:** https://gitlab.com/abanoub.rodolf/mcp-scan

**Body (first comment):**

Every MCP server you install gets filesystem, network, and often shell access to
your machine. mcp-scan audits your Claude Desktop, VS Code, Cursor, Windsurf,
Zed, Cline, and 11 more client configs for:

- Leaked secrets (52+ formats plus entropy analysis, Luhn-validated cards, gated
  prefix-less token formats)
- Prompt injection and tool poisoning in descriptions
- Typosquatting and supply-chain trust scoring
- Real CVEs (live OSV + a bundled offline snapshot covering 74 packages)
- PII handling, data exfiltration vectors, transport and permission risks

I just finished a full self-audit of the tool itself: stored XSS in the HTML
reports, a command injection in `doctor`, and a raw-traffic proxy log were all
closed, and the false-positive classes that made scanners noisy were eliminated
(UUIDs flagged as Pinecone keys, 13-digit numbers flagged as cards, `postgres`
flagged as `POST` exfiltration). 244 tests, full before/after in the repo.

One command, zero telemetry: `npx mcp-scan@latest`. Offline mode for air-gapped
machines. SARIF output drops into GitHub code scanning; GitHub Action included.

**Timing note:** Best posted on weekday mornings, 8-10am ET. Show HN posts must
start with "Show HN:".

---

## Reddit r/cybersecurity

**Title:** mcp-scan: open-source security scanner for MCP (Model Context Protocol) server configs

**Body:**

MCP servers run with full filesystem and network access. Most people install them without auditing what they're actually running.

mcp-scan detects MCP server configs across 17 AI tool clients (Claude Desktop, Cursor, VS Code, Windsurf, Codex CLI, Claude Code, Zed, GitHub Copilot, Cline, Roo Code, Gemini CLI, and more) and runs 16 security scanners against them.

What it checks:

- Leaked secrets and API keys (regex + entropy analysis)
- Known CVEs in MCP packages (live OSV + offline snapshot)
- Dangerous permission patterns
- Transport security (HTTP vs HTTPS)
- Supply chain risks (typosquatting, trust scoring)
- Tool poisoning and capability injection
- Prompt injection in tool descriptions
- PII handling and data exfiltration vectors

Output formats: CLI table, JSON, SARIF (GitHub Security tab), HTML report, CycloneDX/SPDX SBOM.

One command: `npx mcp-scan@latest`

GitHub: https://gitlab.com/abanoub.rodolf/mcp-scan
npm: https://www.npmjs.com/package/mcp-scan

GitHub Action included for CI/CD integration.

**Note on r/netsec:** That subreddit has strict rules against self-promotion and requires established community participation history. Use r/cybersecurity instead, or only post to r/netsec if you have prior participation history there.

---

## Reddit r/ClaudeAI

**Title:** I built mcp-scan, a security scanner for your MCP server configs (found a real exposed token in my own setup)

**Body:**

If you use MCP servers with Claude Desktop, they run with full access to your filesystem and network. mcp-scan checks your configs for:

- Secrets and API keys accidentally left in config files
- Known vulnerabilities in MCP packages
- Suspicious permission patterns
- Exfiltration vectors
- Tool poisoning and prompt injection

It auto-detects configs for 17 AI clients: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Cline, Roo Code, Gemini CLI, Codex CLI, and more.

One command: `npx mcp-scan@latest`

https://gitlab.com/abanoub.rodolf/mcp-scan

---

## Reddit r/LocalLLaMA

**Title:** mcp-scan: security scanner that audits MCP server configs across 17 AI clients

**Body:**

Built a CLI tool that scans your MCP (Model Context Protocol) server configurations for security issues. MCP servers get broad system access and most people never audit what they're running.

Supports Claude Desktop, Cursor, VS Code, Windsurf, Codex CLI, Zed, GitHub Copilot, Cline, Roo Code, Claude Code, Gemini CLI, and more.

16 scanners: secrets, CVEs, permissions, transport, registry, license, supply chain, typosquatting, tool poisoning, exfiltration, AST analysis, config validation, prompt injection, data flow, network egress, data controls.

`npx mcp-scan@latest`

GitHub: https://gitlab.com/abanoub.rodolf/mcp-scan

---

## X/Twitter thread

1. MCP servers run with full filesystem + network access on your machine. Most people install them without ever reading what they run.

2. mcp-scan audits your MCP server configs across 17 AI clients for secrets, prompt injection, typosquatting, CVEs, and data exfiltration.

3. `npx mcp-scan@latest` — no install, no signup, no telemetry. Offline mode included.

4. SARIF output drops straight into GitHub code scanning. GitHub Action included.

5. I also audited mcp-scan itself: closed stored XSS, a command injection, and a raw-traffic log; killed the false-positive classes that made scanners noisy. 244 tests. Full report in the repo.

Star the repo if it's useful: gitlab.com/abanoub.rodolf/mcp-scan

---

## LinkedIn

**Title:** I audited the MCP ecosystem's security tooling — and then audited my own tool

**Body:**

MCP servers are the new attack surface for AI development. They run with filesystem, network, and shell access, and most developers install them without auditing what they execute.

mcp-scan is an open-source scanner that audits MCP server configurations across 17 AI clients (Claude, VS Code, Cursor, Windsurf, Zed, and more) for:

- Exposed secrets (52+ formats + entropy analysis)
- Prompt injection and tool poisoning
- Supply-chain and typosquatting risks
- Known CVEs, PII handling, and data exfiltration

One command: `npx mcp-scan@latest`. Zero telemetry, offline mode, SARIF for CI.

I just completed a full security audit of mcp-scan itself: closed a stored XSS in HTML reports, a command injection in the doctor command, and raw unmasked traffic in the proxy log, and eliminated entire false-positive classes. 244 tests passing; the full before/after record is published with the repo.

MIT licensed: gitlab.com/abanoub.rodolf/mcp-scan

---

## MCP community subreddits (check before posting)

Before posting, check for active MCP-focused subreddits. Search Reddit for:
- r/mcp_servers
- r/ModelContextProtocol
- r/mcptools

These communities are forming and may be receptive to security tooling. Verify activity level before investing time in a post.
