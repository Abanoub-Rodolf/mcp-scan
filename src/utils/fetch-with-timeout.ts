/**
 * fetch() with an abort-based timeout. The timer is always cleared via
 * finally, so a rejected fetch never leaks a pending timer.
 */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs: number = 10000
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}
