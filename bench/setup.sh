#!/usr/bin/env bash
# Installs the competitor scanners the benchmark compares against, each in its own
# venv (their dependency pins conflict). Pinned so a rerun scores the same code.
# Needs uv and network access to pypi.org.
set -euo pipefail
cd "$(dirname "$0")"
CISCO_VERSION="4.8.7"
SNYK_VERSION="0.6.11"
uv venv --python 3.13 .venv-cisco >/dev/null
uv pip install --python .venv-cisco/bin/python "cisco-ai-mcp-scanner==${CISCO_VERSION}"
.venv-cisco/bin/mcp-scanner --help >/dev/null && echo "cisco mcp-scanner ${CISCO_VERSION} ready"
uv venv --python 3.13 .venv-snyk >/dev/null
uv pip install --python .venv-snyk/bin/python "snyk-agent-scan==${SNYK_VERSION}"
.venv-snyk/bin/snyk-agent-scan --help >/dev/null && echo "snyk-agent-scan ${SNYK_VERSION} ready (needs SNYK_TOKEN to analyze)"
