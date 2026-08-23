
import path from 'path';
import fg from 'fast-glob';

type RootKind = 'home' | 'appData' | 'userProfile';

// One row per supported tool. Adding a tool means adding a single entry;
// every platform branch is derived from this table, so a missing platform
// can no longer silently drop a tool.
const TOOL_PATHS: Array<{
  tool: string;
  darwin: [RootKind, ...string[]];
  win32: [RootKind, ...string[]];
  linux: [RootKind, ...string[]];
}> = [
  {
    tool: 'Claude Desktop',
    darwin: ['home', 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'],
    win32: ['appData', 'Claude', 'claude_desktop_config.json'],
    linux: ['home', '.config', 'Claude', 'claude_desktop_config.json'],
  },
  { tool: 'Cursor', darwin: ['home', '.cursor', 'mcp.json'], win32: ['userProfile', '.cursor', 'mcp.json'], linux: ['home', '.cursor', 'mcp.json'] },
  { tool: 'VS Code', darwin: ['home', '.vscode', 'mcp.json'], win32: ['userProfile', '.vscode', 'mcp.json'], linux: ['home', '.vscode', 'mcp.json'] },
  { tool: 'Claude Code', darwin: ['home', '.claude.json'], win32: ['userProfile', '.claude.json'], linux: ['home', '.claude.json'] },
  { tool: 'Windsurf', darwin: ['home', '.codeium', 'windsurf', 'mcp_config.json'], win32: ['userProfile', '.codeium', 'windsurf', 'mcp_config.json'], linux: ['home', '.codeium', 'windsurf', 'mcp_config.json'] },
  { tool: 'Gemini CLI', darwin: ['home', '.gemini', 'settings.json'], win32: ['userProfile', '.gemini', 'settings.json'], linux: ['home', '.gemini', 'settings.json'] },
  { tool: 'Codex CLI', darwin: ['home', '.codex', 'config.toml'], win32: ['userProfile', '.codex', 'config.toml'], linux: ['home', '.codex', 'config.toml'] },
  { tool: 'Zed', darwin: ['home', '.config', 'zed', 'settings.json'], win32: ['userProfile', '.config', 'zed', 'settings.json'], linux: ['home', '.config', 'zed', 'settings.json'] },
  { tool: 'Continue.dev', darwin: ['home', '.continue', 'config.json'], win32: ['userProfile', '.continue', 'config.json'], linux: ['home', '.continue', 'config.json'] },
  { tool: 'Amp', darwin: ['home', '.amp', 'config.json'], win32: ['userProfile', '.amp', 'config.json'], linux: ['home', '.amp', 'config.json'] },
  { tool: 'Plandex', darwin: ['home', '.plandex', 'config.json'], win32: ['userProfile', '.plandex', 'config.json'], linux: ['home', '.plandex', 'config.json'] },
  {
    tool: 'ChatGPT Desktop',
    darwin: ['home', 'Library', 'Application Support', 'com.openai.chat', 'settings.json'],
    win32: ['appData', 'com.openai.chat', 'settings.json'],
    linux: ['home', '.config', 'com.openai.chat', 'settings.json'],
  },
  { tool: 'GitHub Copilot', darwin: ['home', '.config', 'github-copilot', 'apps.json'], win32: ['userProfile', '.config', 'github-copilot', 'apps.json'], linux: ['home', '.config', 'github-copilot', 'apps.json'] },
  {
    tool: 'Kiro',
    darwin: ['home', 'Library', 'Application Support', 'Kiro', 'User', 'mcp.json'],
    win32: ['appData', 'Kiro', 'User', 'mcp.json'],
    linux: ['home', '.config', 'Kiro', 'User', 'mcp.json'],
  },
  { tool: 'Warp', darwin: ['home', '.warp', 'mcp.json'], win32: ['userProfile', '.warp', 'mcp.json'], linux: ['home', '.warp', 'mcp.json'] },
];

function resolveToolPath(segments: [RootKind, ...string[]], roots: Record<RootKind, string>): string {
  const [root, ...rest] = segments;
  return path.join(roots[root], ...rest);
}

export function getConfigPaths(dependencies: { homedir: () => string, platform: () => string, env: NodeJS.ProcessEnv }) {
  const home = dependencies.homedir();
  const platform = dependencies.platform();
  const appData = dependencies.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const userProfile = dependencies.env.USERPROFILE || home;

  const roots: Record<RootKind, string> = { home, appData, userProfile };
  const platformKey = platform === 'darwin' ? 'darwin' : platform === 'win32' ? 'win32' : 'linux';

  const paths: Record<string, string> = {};
  for (const spec of TOOL_PATHS) {
    paths[spec.tool] = resolveToolPath(spec[platformKey], roots);
  }

  return paths;
}

export async function getExtensionGlobPaths(toolName: 'Cline' | 'Roo Code', dependencies: { homedir: () => string }): Promise<string[]> {
  const home = dependencies.homedir();
  const baseVsCodeExtensionsPath = path.join(home, '.vscode', 'extensions');
  let globPattern: string;

  if (toolName === 'Cline') {
    globPattern = 'saoudrizwan.claude-dev*/settings.json';
  } else if (toolName === 'Roo Code') {
    globPattern = 'rooveterinaryinc.roo-cline*/settings.json';
  } else {
    return [];
  }

  const matchedPaths = await fg(path.join(baseVsCodeExtensionsPath, globPattern), {
    cwd: baseVsCodeExtensionsPath,
    absolute: true,
    onlyFiles: true,
    dot: true,
    deep: 1
  });

  return matchedPaths;
}

export function getProjectLevelPaths(dependencies: { cwd: () => string }) {
  const cwd = dependencies.cwd();
  return [
    path.join(cwd, '.mcp.json'),
    path.join(cwd, 'mcp.json'),
    path.join(cwd, '.cursor', 'mcp.json'),
    path.join(cwd, '.vscode', 'mcp.json'),
    path.join(cwd, '.gemini', 'settings.json'),
    path.join(cwd, '.codex', 'config.toml'),
    path.join(cwd, '.amp', 'config.json'),
    path.join(cwd, '.continue', 'config.json'),
  ];
}
