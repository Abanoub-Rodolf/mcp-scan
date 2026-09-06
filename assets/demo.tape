Output assets/demo.gif

Set Shell zsh
Set FontSize 15
Set Width 1400
Set Height 950
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

# Real npx users would run `npx mcp-scan@latest`, which fetches from the
# registry: not deterministic or offline-safe for a recording. Fake a local
# npx on PATH that runs the built CLI with no --config, so it auto-detects
# the two client configs planted under a scratch $HOME instead. The repo-hint
# marker is cleared so the post-scan star hint (fires once per machine)
# actually shows up in the recording.
Hide
Type "mkdir -p /tmp/mcp-scan-demo/bin"
Enter
Type "echo '#!/bin/sh' > /tmp/mcp-scan-demo/bin/npx"
Enter
Type "echo exec node $PWD/dist/index.js --offline >> /tmp/mcp-scan-demo/bin/npx"
Enter
Type "chmod +x /tmp/mcp-scan-demo/bin/npx"
Enter
Type "export PATH=/tmp/mcp-scan-demo/bin:$PATH HOME=/tmp/mcp-scan-demo/home MCP_SCAN_HOME=/tmp/mcp-scan-demo/home/.mcp-scan"
Enter
Type "rm -f $MCP_SCAN_HOME/repo-hint-shown"
Enter
Type "clear"
Enter
Show

Type "npx mcp-scan@latest"
Sleep 500ms
Enter
Sleep 6s
