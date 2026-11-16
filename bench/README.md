# Benchmark: poisoned vs honest MCP servers

Does a scanner flag what a malicious MCP server tells the model, without flagging honest servers? This directory answers that for mcp-scan and two competitors on a labeled corpus, and anyone can rerun it.

```bash
npm run build                    # the benchmark imports dist/lib.js
bench/setup.sh                   # installs pinned competitors into bench/.venv-* (needs uv, network)
node bench/run.mjs               # mcp-scan only needs no setup; competitors run if installed
SNYK_TOKEN=... node bench/run.mjs   # Snyk agent-scan analyzes on Snyk's backend and needs a token
```

Results land in `bench/results/latest.md` and `latest.json` (per-sample rows included).

## What is scored

One verdict per sample: did the scanner flag it. The sample is the catalog a server serves (`tools/list`, `prompts/list`, `resources/list`, server instructions), recorded from the published source, so no scanner starts a server.

| Scanner | What runs | Flag means |
|---|---|---|
| mcp-scan static (2.3.0 checks) | `scanToolPoisoning` + `scanPromptInjection` over the schema blob, the checks 2.3.0 applied to tool text | any HIGH finding |
| mcp-scan `--live` | `scanLive` on the catalog (what `scan --live` runs after connecting) | any MEDIUM or HIGH finding |
| Cisco mcp-scanner 4.8.7 | `--analyzers yara static`, the only mode that needs no credentials | `is_safe: false` |
| Snyk agent-scan 0.6.11 | not scored unless `SNYK_TOKEN` is set; its analysis runs on api.snyk.io | `prompt_injection_tool_desc` score of 300 or more |

Rug pulls are scored apart: for samples that carry a `before` catalog, did the snapshot diff report a change.

## Corpus

`corpus/poisoned/`: samples from public write-ups and public proof-of-concept repositories, each with its URL, author and license in `SOURCES.md`. mcp-scan's own regexes were never used to pick or write a sample. `corpus/benign/`: tool catalogs recorded from real npm MCP servers with `capture.mjs` (package and version in each file).

Benign samples carry a `set`: `tuning` servers were visible while the mcp-scan heuristics were being written, so precision on them is in-sample; `holdout` servers were recorded afterwards and scanned before any further change. Read the holdout number as the honest one.

## Limits

- Small corpus: 51 poisoned, 27 benign. A single sample moves recall by about 2 points.
- Sources overlap with competitors' own test data (11 samples are Cisco's fixtures, 2 are Snyk's, 9 are sampled from the MCPTox benchmark). Those favor neither side in a controlled way; per-source rows are in `latest.json`.
- Cisco ran with its YARA analyzer only. Its LLM and API analyzers need keys, so its recall with those on is not measured here.
- Catalog-level attacks only. Payloads that appear in tool output or sampling requests need a running agent and are excluded.
- Full-schema poisoning has no samples: the primary write-up could not be fetched.
- The mcp-scan rules were written from the published attack patterns, not from these samples, with one disclosed exception: reviewers' false-negative examples widened two rules (an absolute-path credentials read, a secret sent through a sidenote parameter), moving recall from 62.7% to 66.7%. Those two points are in-sample. Anyone who tunes the rules on this corpus must say so.
- Cisco is given `tools`, `prompts` and `resources` only, not server `instructions`, so an instruction-only sample cannot be caught by it.
- The rug-pull row shows the snapshot diff reports a changed definition; the corpus has no benign before/after control, so it is not a false-positive measure.
