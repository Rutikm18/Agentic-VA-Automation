// SSE broadcast bus — shared between ingest API and SSE stream endpoint

type Callback = (data: string) => void;

const scanListeners: Map<string, Set<Callback>> = new Map();

export function subscribeScan(scanId: string, callback: Callback): () => void {
  let listeners = scanListeners.get(scanId);
  if (!listeners) {
    listeners = new Set();
    scanListeners.set(scanId, listeners);
  }
  listeners.add(callback);
  return () => {
    listeners!.delete(callback);
    if (listeners!.size === 0) scanListeners.delete(scanId);
  };
}

export function broadcastToScan(scanId: string, event: string, data: object): void {
  const listeners = scanListeners.get(scanId);
  if (!listeners || listeners.size === 0) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const cb of listeners) {
    try { cb(payload); } catch { /* ignore dead listeners */ }
  }
}
