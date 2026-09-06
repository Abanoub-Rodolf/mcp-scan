# Known issue: launched this way inside ttyd's pty, the dashboard either
# crashes ("Failed to launch dashboard: Width must be multiple of 2!",
# thrown by the donut widget's canvas sizing in drawille-blessed-contrib)
# or exits 0 with nothing drawn. The same build renders fine outside ttyd
# (plain pty, same terminal size). No working dashboard.gif until that's
# sorted upstream or the donut widget is swapped out.
Output assets/dashboard.gif

Set Shell zsh
Set FontSize 16
Set Width 1000
Set Height 560
Set Theme "Catppuccin Mocha"
Set Padding 24
Set TypingSpeed 40ms

Hide
Type "mkdir -p /tmp/mcp-scan-demo/bin"
Enter
Type "echo '#!/bin/sh' > /tmp/mcp-scan-demo/bin/npx"
Enter
Type "echo 'if [ $1 = dashboard ]; then' >> /tmp/mcp-scan-demo/bin/npx"
Enter
Type "echo '  exec node ${PWD}/dist/index.js dashboard' >> /tmp/mcp-scan-demo/bin/npx"
Enter
Type "echo else >> /tmp/mcp-scan-demo/bin/npx"
Enter
Type "echo '  exec node ${PWD}/dist/index.js --config ${PWD}/tests/fixtures/vulnerable-config.json --offline' >> /tmp/mcp-scan-demo/bin/npx"
Enter
Type "echo fi >> /tmp/mcp-scan-demo/bin/npx"
Enter
Type "chmod +x /tmp/mcp-scan-demo/bin/npx"
Enter
Type "export PATH=/tmp/mcp-scan-demo/bin:$PATH MCP_SCAN_HOME=/tmp/mcp-scan-demo/home"
Enter
Type "npx mcp-scan >/dev/null 2>&1"
Enter
Type "clear"
Enter
Show

Type "npx mcp-scan dashboard"
Sleep 500ms
Enter
Sleep 5s
Type "q"
Sleep 1s
