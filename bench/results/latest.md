Corpus: 51 poisoned (published proofs of concept), 27 benign (real npm servers). Generated 2026-11-16.

| Scanner | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| mcp-scan static (2.3.0 checks) | 53.8% | 13.7% | 0.22 | 7 | 6 | 44 | 21 |
| mcp-scan --live | 100.0% | 66.7% | 0.80 | 34 | 0 | 17 | 27 |
| cisco mcp-scanner 4.8.7 (yara) | 69.0% | 39.2% | 0.50 | 20 | 9 | 31 | 18 |
| snyk agent-scan 0.6.11 | 100.0% | 45.1% | 0.62 | 23 | 0 | 28 | 27 |

Recall by category:

| Category | n | mcp-scan static (2.3.0 checks) | mcp-scan --live | cisco mcp-scanner 4.8.7 (yara) | snyk agent-scan 0.6.11 |
|---|---|---|---|---|---|
| cross-tool | 7 | 0.0% | 57.1% | 0.0% | 14.3% |
| exfil-param | 4 | 50.0% | 50.0% | 50.0% | 75.0% |
| hidden-unicode | 1 | 0.0% | 100.0% | 0.0% | 0.0% |
| prompt-injection-prompt | 1 | 0.0% | 0.0% | 0.0% | 0.0% |
| resource-injection | 1 | 0.0% | 0.0% | 0.0% | 0.0% |
| rug-pull-after | 4 | 0.0% | 100.0% | 75.0% | 75.0% |
| tool-poisoning | 24 | 20.8% | 62.5% | 45.8% | 50.0% |
| tool-shadowing | 9 | 0.0% | 88.9% | 44.4% | 44.4% |

Holdout benign servers (recorded after the rules were written): 14; mcp-scan --live flagged 0.

Rug pulls (changed definition after approval): snapshot diff reported 4 of 4 (no benign control, so this shows the diff works, not its false-positive rate).
