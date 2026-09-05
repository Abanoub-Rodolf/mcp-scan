# mcp-scan launch announcements (v2.0.3 / v2.0.4)

All copy below reflects the shipped 2.0.3/2.0.4 state. Verified facts: 246 tests, 16 scanners, 19 commands, 5 compliance frameworks, 2 SBOM formats, tool-catalog injection coverage, OIDC provenance publishing, SARIF GitHub Action, zero telemetry. The full audit record: https://gitlab.com/abanoub.rodolf/mcp-scan

---

**Twitter/X Thread:**

1/ mcp-scan 2.0.3 is out — and this release hardened the scanner itself. We ran a full end-to-end security audit of mcp-scan and fixed what we found. Stored XSS in HTML reports. Command injection in `doctor`. A proxy that logged raw traffic to disk. All closed.

2/ The interesting part: MCP threat models changed. Tool catalogs are part of the prompt now. Tool names, descriptions, and nested JSON-schema fields all enter model context at tools/list time — so injection payloads hide in schemas, not just descriptions.

3/ Our prompt-injection and tool-poisoning scanners now recursively scan the whole schema.tools structure, keys included. Regression tests prove payloads buried in a nested inputSchema description get caught.

4/ Also fixed: CVE scanner was silently dropping CVSS v4 scores and the upgrade advisor recommended upgrades exactly when they fixed nothing. Compliance mappings and the SARIF rule table had dead finding IDs — now generated from the real emitted set, no drift.

5/ Distribution got hardened too: npm publishing now runs on OIDC trusted publishing — no tokens, full provenance attestation on every release. 2.0.4 is provenance-signed.

6/ 246 tests, 16 scanners, zero telemetry. `npx mcp-scan@latest` to scan your Claude/Cursor/Windsurf/VS Code MCP configs. gitlab.com/abanoub.rodolf/mcp-scan

**LinkedIn Post:**

mcp-scan 2.0.3: we audited our own scanner, and it found real problems.

A full end-to-end security audit of mcp-scan's 16 scanners, 19 commands, and CLI core surfaced issues we're now shipping fixes for:

- Stored XSS in HTML reports (server-controlled strings interpolated unescaped)
- Command injection in `mcp-scan doctor`
- A proxy that logged raw unmasked traffic to disk
- A CVE scanner silently dropping CVSS v4 scores
- Compliance/SARIF mappings referencing finding IDs the scanners never emitted

The deeper finding is about the MCP threat model itself: tool catalogs are part of the prompt. Tool names, descriptions, and nested JSON-schema values enter model context at tools/list time, so injection payloads hide in schemas. Our prompt-injection and tool-poisoning scanners now recursively scan the entire tool catalog, keys included, with regression tests proving schema-embedded payloads are caught.

246 tests passing. npm publishing now runs on OIDC trusted publishing with full provenance attestation. Zero telemetry — nothing leaves your machine.

Audit record: gitlab.com/abanoub.rodolf/mcp-scan

`npx mcp-scan@latest`

#MCP #AISecurity #LLMSecurity #OpenSource #Infosec

**Reddit Post (r/cybersecurity / r/MCP / r/LocalLLaMA):**

**Title:** We audited our own MCP security scanner — and found stored XSS, command injection, and a CVE scanner dropping data. mcp-scan 2.0.3 fixes all of it.

I maintain mcp-scan, an open-source scanner that audits MCP server configs across Claude Desktop, VS Code, Cursor, Windsurf, and 12 more clients. I ran a full end-to-end audit of the tool itself. Here's what it found:

**Security fixes:**
- Stored XSS in HTML reports: server-controlled strings interpolated unescaped
- Command injection in `mcp-scan doctor` (which ran through a shell)
- Proxy logged raw unmasked traffic to disk (now configurable via MCP_SCAN_LOG_DIR)
- CVE scanner silently dropped CVSS v4 and plain numeric scores; upgrade advisor recommended upgrades exactly when they fixed nothing
- Secret scanner flagged UUIDs and bare token-length strings as CRITICAL (false positives eliminated)
- PII cascade bugs: Luhn validation, private-IP exclusion, `/g` lastIndex silent-detection

**The threat-model insight:** in 2026, the tool catalog is part of the prompt. Tool names, descriptions, and nested JSON-schema description/enum values enter model context at tools/list time. Injection payloads hide in schema fields, not just server descriptions. Our prompt-injection and tool-poisoning scanners now recursively scan the entire schema.tools structure, keys included — with regression tests proving schema-embedded payloads are caught.

**Also shipped:** OIDC trusted publishing with provenance attestation on npm (no tokens, verifiable builds), SARIF output for GitHub code scanning, standalone-bundled GitHub Action (was crashing with "Cannot find module semver").

246 tests passing, 16 scanners, 19 commands, compliance mapping to SOC 2/GDPR/HIPAA/PCI-DSS/NIST, SBOM in CycloneDX/SPDX. Zero telemetry.

Full audit record with every finding and fix: https://gitlab.com/abanoub.rodolf/mcp-scan

`npx mcp-scan@latest` to try it. Feedback welcome — especially on the tool-catalog scanning approach.

**Hacker News (Show HN draft):**

**Title:** Show HN: mcp-scan 2.0.3 – I audited my own MCP security scanner and fixed what it found

We scan MCP server configs for Claude Desktop, VS Code, Cursor, Windsurf + 12 more clients: secrets, prompt injection, supply-chain, data-flow, network egress, compliance mapping (SOC 2/GDPR/HIPAA/PCI-DSS/NIST), SBOM.

This release is the result of auditing the scanner itself:
- Stored XSS in HTML reports, command injection in `doctor`, proxy logging raw traffic — all closed
- CVE scanner was silently dropping CVSS v4 scores; upgrade advice was inverted
- Compliance/SARIF mappings referenced finding IDs scanners never emit — now generated from the real set

The interesting part is the MCP threat model. Tool catalogs enter model context at tools/list time — names, descriptions, nested JSON-schema fields. So injection payloads hide in schemas. The prompt-injection and tool-poisoning scanners now recursively scan the whole tool catalog, keys included, with regression tests for schema-embedded payloads.

Distribution: npm publishing now runs on OIDC trusted publishing with provenance attestation — 2.0.4 is provenance-signed, no tokens anywhere.

246 tests, zero telemetry, MIT. `npx mcp-scan@latest`. Audit record: https://gitlab.com/abanoub.rodolf/mcp-scan

---

**B站 / 小红书 (中文):**

**标题：** 我把自己的 MCP 安全扫描器审计了一遍，发现了存储型 XSS 和命令注入

mcp-scan 2.0.3 发布。这个开源工具扫描 Claude Desktop、VS Code、Cursor、Windsurf 等 17 款 AI 客户端的 MCP 服务器配置，检测密钥泄露、提示注入、供应链风险。

这次我们对工具本身做了完整的安全审计并修复了发现的问题：
- HTML 报告存储型 XSS（服务端可控字符串未转义）
- `mcp-scan doctor` 命令注入（which 走了 shell）
- 代理把原始流量明文写入磁盘（现在可用 MCP_SCAN_LOG_DIR 配置）
- CVE 扫描器静默丢弃 CVSS v4 分数，升级建议方向颠倒
- 合规映射和 SARIF 规则表引用了扫描器从不发出的 finding ID（已改为从真实 ID 生成）

更重要的发现是 MCP 威胁模型的变化：2026 年工具目录本身就是提示词的一部分。工具名、描述、嵌套 JSON schema 的 description/enum 都会在 tools/list 时进入模型上下文，注入载荷藏在 schema 字段里而不是 server.description。prompt-injection 和 tool-poisoning 扫描器现在递归扫描整个 schema.tools（含 key），并有回归测试证明 schema 内嵌载荷能被命中。

246 个测试通过，零遥测，MIT 协议。npm 发布已切换到 OIDC 可信发布，2.0.4 带 provenance 签名。

审计全文：https://gitlab.com/abanoub.rodolf/mcp-scan

`npx mcp-scan@latest`

#MCP #AI安全 #LLM安全 #开源 #安全审计
