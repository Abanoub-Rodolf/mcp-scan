# Poisoned MCP corpus: sources

Every sample is a catalog-level payload (tools/list, prompts/list, resources/list) taken from the public source below. Nothing was executed; repos were shallow-cloned and read, blogs were fetched as raw HTML. Collected 2026-11-15. `verbatim: false` marks samples where something was reconstructed (explained in each file's `notes`).

| Source | Author | Date | Samples | License | Verbatim payload fetched |
|---|---|---|---|---|---|
| https://github.com/invariantlabs-ai/mcp-injection-experiments | Invariant Labs (Beurer-Kellner, Fischer) | 2025-04 | 3 | none stated in repo | yes (3 of 3) |
| https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks | Invariant Labs | 2025-04-01 | 2 | blog, not stated | 1 yes; the shadowing one has the email restored from the repo (page obfuscates it) |
| https://invariantlabs.ai/blog/whatsapp-mcp-exploited | Invariant Labs | 2025-04-07 | 1 (rug pull pair) | blog, not stated | yes |
| https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/ | Trail of Bits | 2025-04-21 | 1 | blog, not stated | description yes; tool name not shown on the page (taken from Cisco's copy), so verbatim=false |
| https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/ | Keith Hoodlet, Trail of Bits | 2025-04-29 | 1 | blog, not stated | yes (docstring only; ANSI payloads are tool output, excluded) |
| https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations | Beretta, Carlock, Pease (Elastic Security Labs) | 2025-09-19 | 5 | blog, not stated | yes |
| https://repello.ai/blog/mcp-tool-poisoning-to-rce | Repello AI | 2025-04-17 | 1 | blog, not stated | yes (Elastic reproduces it) |
| https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/ | Johann Rehberger | 2025-05-02 | 2 (1 with U+E00xx tag characters) | blog, not stated | yes |
| https://github.com/harishsg993010/damn-vulnerable-MCP-server | harishsg993010 | unknown (snapshot commit 2026-11-01) | 4 | MIT | yes |
| https://github.com/cisco-ai-defense/mcp-scanner (examples/ and evals/) | Cisco AI Defense | unknown (snapshot 2026-11-05) | 11 | Apache-2.0 | yes |
| https://github.com/riseandignite/mcp-shield (mcp-servers-example) | riseandignite | 2025-04-26 | 5 | MIT | yes |
| https://github.com/snyk/agent-scan (demoserver) | Snyk | unknown (snapshot 2026-11-13) | 2 | Apache-2.0 | yes |
| https://github.com/AIS2Lab/MCPSecBench (code/) | AIS2Lab | unknown (snapshot 2026-03-05) | 4 | MIT | yes |
| https://github.com/zhiqiangwang4/MCPTox-Benchmark | Wang et al., AAAI 2026 | unknown | 9 (sampled from 1348) | CC BY 4.0 (data), MIT (code) | yes, but the dataset stores name and description as flattened text with no JSON schema |

## Not obtained

| Source | Why |
|---|---|
| CyberArk "Poison everywhere" (full-schema poisoning) | cyberark.com now 301-redirects to paloaltonetworks.com/idira; Wayback returned 403; a Jina mirror returned the redirect target. No full-schema samples in the corpus. |
| OWASP MCP Top 10 (github.com/OWASP/www-project-mcp-top-10, CC BY-SA 4.0) | Prose and detection indicators only, no payload definitions. |
| Cisco evals/behavioral-analysis/data/tool-poisoning and evals/remote/malicious | Descriptions are benign or generic; the maliciousness is in function bodies, not the catalog. |
