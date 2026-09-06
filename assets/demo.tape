Output assets/demo.gif

Set Shell zsh
Set FontSize 16
Set Width 1000
Set Height 560
Set Theme "Catppuccin Mocha"
Set Padding 24
Set TypingSpeed 40ms

# Real npx users would run `npx mcp-scan@latest`, which fetches from the
# registry: not deterministic or offline-safe for a recording. Fake a local
# npx on PATH that runs the built CLI against the fixture config instead, so
# the typed command matches what a user sees while the output stays fixed.
# MCP_SCAN_HOME points at a scratch dir so the post-scan star hint (fires
# once per machine) actually shows up in the recording.
Hide
Type "mkdir -p /tmp/mcp-scan-demo/bin"
Enter
Type "echo '#!/bin/sh' > /tmp/mcp-scan-demo/bin/npx"
Enter
Type "echo exec node $PWD/dist/index.js --config $PWD/tests/fixtures/vulnerable-config.json --offline >> /tmp/mcp-scan-demo/bin/npx"
Enter
Type "chmod +x /tmp/mcp-scan-demo/bin/npx"
Enter
Type "export PATH=/tmp/mcp-scan-demo/bin:$PATH MCP_SCAN_HOME=/tmp/mcp-scan-demo/home"
Enter
Type "clear"
Enter
Show

Type "npx mcp-scan@latest"
Sleep 500ms
Enter
Sleep 6s
