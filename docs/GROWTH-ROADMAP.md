# mcp-scan Growth Roadmap

Research date: 2026-08-15. Retrieval: npm registry API, GitHub API, PyPI,
competitor READMEs (agentsec, mcp-guard, mcp-server-security-scanner),
indie-launch retrospectives (dev.to). Sources dated; re-verify volatile
numbers before acting on them.

## Market position (as of 2026-08-15)

- **npm weekly downloads**: mcp-scan 151/wk, trending up (90/wk -> 151/wk
  over the last 30 days). Closest npm neighbors: mcp-server-security-scanner
  187/wk (an MCP *server*, different category), agentsec-ai 40/wk (PyPI),
  mcp-audit 13/wk.
- **GitHub stars**: the entire MCP-security-scanner space is nascent; few
  tools have meaningful stars yet. Distribution is still wide open.
- **Category**: mcp-scan is one of the few *client-config* scanners (audits
  Claude Desktop, VS Code, Cursor, Windsurf configs). Most competitors are
  runtime gateways (proxies that block calls) or MCP *servers* that expose
  scan tools. Static config audit + compliance + SBOM + SARIF is a distinct
  niche with little direct competition.

## Competitive landscape (verified 2026-08-15)

| Tool | Type | Key features | Monetization |
|---|---|---|---|
| agentsec (debu-sinha/agentsec, PyPI agentsec-ai) | CLI scanner, Python | Static config scan + harden profiles (workstation/vps/public-bot), watch/gate/hook modes, detect-secrets, **OWASP Top 10 for Agentic Apps (2026) mapping**, SARIF, GitHub Action | OSS (Apache-2.0), no visible paid tier |
| mcp-server-security-scanner | MCP server | Scans MCP configs/tool defs via MCP tools | OSS |
| mcp-guard | CLI scanner | Policy file, init workflow, audit packs, Stripe self-serve, **documented paid ladder** (Starter Kit $49, Pro $19/mo, Team Setup $199, CI sprint $199-5000) | OSS + paid |
| mcp-audit, agentsec-ai variants, agentaegis, lazaretto, arc-gate etc. | Mixed | Runtime gating, malware checks, lockfile scanning | Mostly OSS, some x402/USDC per-call |

## Biggest competitive gaps to close

1. **OWASP Top 10 for Agentic Applications (2026) mapping** — agentsec has
   it; mcp-scan maps to SOC 2/GDPR/HIPAA/PCI-DSS/NIST but not the OWASP ASI
   set that the AI-security community is standardizing on. Adding
   `compliance --framework owasp-asi` would match the emerging benchmark.
   (Medium effort, high differentiation.)
2. **Harden profiles** — agentsec ships `workstation`/`vps`/`public-bot`
   presets that actually rewrite configs. mcp-scan has a `fix` command but
   no opinionated presets. (Medium effort, high value.)
3. **Watch/gate modes** — agentsec has `watch` (auto re-scan) and `gate`
   (pre-install scan). mcp-scan has proxy + policies but no file-watch or
   pre-install gate. (Medium effort.)
4. **Paid tier** — mcp-guard documents the only real monetization playbook
   in this space. mcp-scan has the same raw material (scanning, SARIF,
   policies) plus the existing $49 mcp-server-starter-pro sibling. A
   self-serve ladder (Starter Kit / Pro / Team Setup / CI sprint) is the
   proven model. (See Monetization below.)
5. **Landing page** — mcp-server-security-scanner and mcp-guard both have
   product pages; mcp-scan's npm homepage points at thynkq.com/products/
   mcp-scan, which is currently stale (shows CLI v2.0.2, we are at 2.0.4).
   Fix that page first: it is the npm homepage.

## Monetization (applies mcp-guard's verified playbook)

| Offer | Price | Buyer |
|---|---|---|
| MCP Audit Starter Kit (templates, action setup, audit handoff template) | $49 one-time | solo dev / indie hacker |
| mcp-scan Pro (private-repo license gate, maintained policy templates, priority support) | $19/mo | team using private repos |
| Team Setup Package (CLI + Action + policy + baseline + SARIF + PR comments + audit pack) | $199 one-time | startup team |
| CI Setup Sprint (setup + onboarding, not a manual audit) | $199-2,000 | companies adopting MCP |

Order of operations:
1. Fix thynkq.com/products/mcp-scan (stale v2.0.2 -> current) — this is the
   npm homepage and the money funnel entry.
2. Wire the existing $49 mcp-server-starter-pro into a Starter Kit bundle
   with a Stripe payment link (self-serve, no sales call).
3. Add `license verify` style entitlement once a Pro tier exists.
4. Outreach copy template (adapted from the verified mcp-guard template):
   "I built mcp-scan, an open-source local scanner for MCP server configs.
   It checks for exposed secrets, prompt injection, tool-catalog poisoning,
   typosquatted packages, CVE-exposed dependencies, network egress, and
   data-flow exfiltration across 17 AI clients, and maps findings to SOC 2/
   GDPR/HIPAA/PCI-DSS/NIST. I am collecting real-world MCP config patterns
   from teams using Claude, Cursor, Windsurf, or MCP in production. If you
   can share a redacted config or run the CLI locally, your feedback helps
   improve the rules and reports."

## Launch sequence (30 days)

Week 1 — ship + announce
- Publish the GitHub releases (done: v2.0.3, v2.0.4 on GitHub + GitLab).
- Show HN post (draft in docs/social/announcements.md). Best time: weekday
  morning US-Eastern, problem-first title with a real number. Even a
  "failed" HN post drives high-quality repo visitors.
- dev.to article: the announcing-v2.md blog post, adapted. dev.to is the
  slow-burn SEO winner — Google/DuckDuckGo index it and send traffic for
  months. Use benchmarks, not feature lists.

Week 2 — communities
- Reddit: r/MCP, r/cybersecurity, r/LocalLLaMA, r/ClaudeAI. Self-promo is
  sensitive: post the audit story (we audited our own scanner) framed as
  research, disclose affiliation. Expect spam-filter removals; message mods.
- LinkedIn: problem-first post ("MCP servers run with full access to your
  filesystem..."). LinkedIn surprised indie devs with reach.
- X/Twitter thread (draft exists).

Week 3 — lists + SEO
- awesome-mcp-servers PR (submitted: #12192) and Awesome-MCP-ZH (submitted:
  #454). Ping maintainers after a week.
- npm search: mcp-scan ranks #1 for its own name but not for "mcp audit";
  ranking is download-velocity-driven — launches in weeks 1-2 fix it.
- Consider Homebrew formula (`brew install mcp-scan`) for the macOS dev
  audience — the npx path already works but Homebrew is a discovery channel.

Week 4 — paid offer + feedback loop
- Stand up the Starter Kit / Pro ladder (Monetization above).
- Collect redacted configs from users; publish a "state of MCP security"
  analysis post (data-driven content compounds).
- Ship one of the gap features (OWASP ASI mapping is the highest-leverage).

## Measurable targets (30 days)

- npm weekly downloads: 151 -> 1,000+
- GitHub stars: 1 -> 100+ (the whole niche is under-starred; a good Show HN
  alone can do this)
- 1-3 paid Starter Kit sales
- Both awesome-list PRs merged
- 2-4 published articles (dev.to + HN + Chinese platforms)

## Non-goals

- No paid ads in the first 30 days (velocity from organic launch is cheaper
  and more credible for a security tool).
- No runtime SaaS before product-market fit on the CLI.
- No spammy cross-posting: one considered post per platform.

## Sources

- agentsec README (github.com/debu-sinha/agentsec)
- mcp-guard business playbook (github.com/ChaoYue0307/mcp-guard)
- npm registry API download counts (api.npmjs.org)
- "I launched an open source CLI tool with zero audience" dev.to/krit83
- awesome-mcp-servers, Awesome-MCP-ZH contribution flows
