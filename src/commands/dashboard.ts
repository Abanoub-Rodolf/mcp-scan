import { createDashboard } from '../utils/dashboard-ui.js';

export async function runDashboard() {
  let dashboard;
  try {
    dashboard = createDashboard();
  } catch (err) {
    // A raw unhandled rejection would exit with a stack trace instead of
    // a user-facing message (e.g. TTY unavailable).
    console.error(`Failed to launch dashboard: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
    return;
  }
  void dashboard;
  
  // Dashboard runs in foreground, wait for user to quit
  return new Promise(() => {});
}
