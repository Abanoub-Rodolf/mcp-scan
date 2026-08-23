import blessed from 'blessed';
import contrib from 'blessed-contrib';
import { DashboardView } from '../types/dashboard.js';
import { readAuditLog } from './audit-logger.js';

import { BRAND_COLOR } from '../types/severity.js';

export function createDashboard() {
  const screen = blessed.screen({
    smartCSR: true,
    title: 'mcp-scan Enterprise Dashboard',
    fullUnicode: true,
  });

  let currentView: DashboardView = 'HISTORY';

  const grid = new contrib.grid({ rows: 12, cols: 12, screen: screen });

  // Header
  grid.set(0, 0, 1, 12, blessed.box, {
    content: `{center}{bold}{#${BRAND_COLOR}-fg}MCP SCAN ENTERPRISE DASHBOARD{/|}{/center}`,
    tags: true,
    style: { fg: 'white', bg: 'black' }
  });

  // Footer / Key bindings
  grid.set(11, 0, 1, 12, blessed.box, {
    content: '{center}Keybindings: [Q] Quit  |  [H] History View  |  [P] Proxy View  |  [R] Refresh{/center}',
    tags: true,
    style: { fg: '#8B949E', bg: 'black' }
  });

  const historyDonut = grid.set(1, 0, 5, 4, contrib.donut, {
    label: ' Overall Severity Breakdown ',
    radius: 8,
    arcWidth: 3,
    remainColor: 'black',
    yPadding: 2,
  });
  
  const historyStatsBox = grid.set(6, 0, 5, 4, blessed.box, {
    label: ' System Stats ',
    content: 'Loading...',
    tags: true,
    style: { fg: 'white', bg: 'black', border: { fg: '#30363d' } }
  });

  const historyTable = grid.set(1, 4, 10, 8, contrib.table, {
    keys: true,
    fg: 'white',
    selectedFg: 'white',
    selectedBg: BRAND_COLOR,
    interactive: true,
    label: ' Recent Scans (Use UP/DOWN to scroll) ',
    width: '100%',
    height: '100%',
    border: { type: "line", fg: "#30363d" },
    columnSpacing: 2,
    columnWidth: [22, 10, 20, 15]
  });

  const proxyLog = grid.set(1, 0, 10, 8, contrib.log, {
    fg: 'green',
    selectedFg: 'green',
    label: ' Proxy Traffic (JSON-RPC) ',
    border: { type: "line", fg: BRAND_COLOR }
  });

  const proxyStats = grid.set(1, 8, 10, 4, blessed.box, {
    label: ' Proxy Stats ',
    tags: true,
    content: '\n {bold}Traffic Volume:{/bold} 0 msgs\n {bold}PII Blocked:{/bold} 0 hits\n {bold}Status:{/bold} {green-fg}ACTIVE{/green-fg}',
    style: { fg: 'white', bg: 'black', border: { fg: '#30363d' } }
  });

  proxyLog.hide();
  proxyStats.hide();

  function aggregateHistory(entries: Array<{ scannedCount: number; findings: { critical: number; high: number; medium: number; low: number } }>) {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    let totalScanned = 0;
    for (const e of entries) {
      totalScanned += e.scannedCount;
      bySeverity.critical += e.findings.critical;
      bySeverity.high += e.findings.high;
      bySeverity.medium += e.findings.medium;
      bySeverity.low += e.findings.low;
    }
    // Guard against divide-by-zero when the log is empty or all-clean.
    const total = bySeverity.critical + bySeverity.high + bySeverity.medium + bySeverity.low || 1;
    return { totalScanned, bySeverity, total };
  }

  function updateHistoryView() {
    if (currentView !== 'HISTORY') return;

    const entries = readAuditLog(20);
    const history = aggregateHistory(entries);
    historyStatsBox.setContent(`\n {bold}Total Scans in Log:{/bold} ${entries.length}\n {bold}Servers Analyzed:{/bold} ${history.totalScanned}\n {bold}Latest Scan:{/bold} ${entries[0] ? new Date(entries[0].timestamp).toLocaleTimeString() : 'N/A'}`);

    historyDonut.setData([
      { percent: Math.round((history.bySeverity.critical/history.total)*100), label: 'CRITICAL', color: 'red' },
      { percent: Math.round((history.bySeverity.high/history.total)*100), label: 'HIGH', color: 'yellow' },
      { percent: Math.round((history.bySeverity.medium/history.total)*100), label: 'MEDIUM', color: 'cyan' },
      { percent: Math.round((history.bySeverity.low/history.total)*100), label: 'LOW', color: 'green' }
    ]);

    const tableData = entries.map(e => [
      new Date(e.timestamp).toLocaleString(),
      e.scannedCount.toString(),
      `${e.findings.critical}/${e.findings.high}/${e.findings.medium}/${e.findings.low}`,
      `${e.durationMs}ms`
    ]);
    
    historyTable.setData({ headers: ['Timestamp', 'Servers', 'Findings (C/H/M/L)', 'Duration'], data: tableData });
    screen.render();
  }

  function switchView(view: DashboardView) {
    currentView = view;
    if (view === 'HISTORY') {
      proxyLog.hide();
      proxyStats.hide();
      historyDonut.show();
      historyStatsBox.show();
      historyTable.show();
      historyTable.focus();
      updateHistoryView();
    } else {
      historyDonut.hide();
      historyStatsBox.hide();
      historyTable.hide();
      proxyLog.show();
      proxyStats.show();
      proxyLog.focus();
      screen.render();
    }
  }

  let totalProxyMsgs = 0;
  let totalPiiHits = 0;

  function appendProxyLog(direction: string, message: string, piiDetected: boolean = false) {
    totalProxyMsgs++;
    if (piiDetected) totalPiiHits++;
    
    const color = direction.includes('CLIENT') ? '{cyan-fg}' : '{magenta-fg}';
    let displayMsg = message.length > 150 ? message.substring(0, 147) + '...' : message;
    if (piiDetected) {
       displayMsg = `{red-bg}{white-fg}PII MASKED{/white-fg}{/red-bg} ${displayMsg}`;
    }
    
    proxyLog.log(`${color}[${direction}]{/} ${displayMsg}`);
    
    proxyStats.setContent(`\n {bold}Traffic Volume:{/bold} ${totalProxyMsgs} msgs\n {bold}PII Blocked:{/bold} ${totalPiiHits} hits\n {bold}Status:{/bold} {green-fg}ACTIVE{/green-fg}`);
    
    if (currentView === 'PROXY') screen.render();
  }

  screen.key(['escape', 'q', 'C-c'], function() {
    screen.destroy();
    return process.exit(0);
  });

  screen.key(['h', 'H'], () => switchView('HISTORY'));
  screen.key(['p', 'P'], () => switchView('PROXY'));
  screen.key(['r', 'R'], () => updateHistoryView());
  screen.key(['down', 'up'], () => {
    if (currentView === 'HISTORY') historyTable.focus();
  });

  switchView('HISTORY');

  return { screen, grid, updateHistoryView, appendProxyLog, switchView };
}
