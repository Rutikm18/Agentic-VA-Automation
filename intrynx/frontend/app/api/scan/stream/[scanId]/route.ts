import { NextRequest } from "next/server";
import { subscribeScan } from "../../../../../lib/scan-events";

const HEARTBEAT_MS = 15_000;

// GET /api/scan/stream/[scanId] — SSE stream for live scan events
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const { scanId } = await params;
  const enc        = new TextEncoder();

  let heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  let unsubscribe: (() => void) | undefined;

  const stream = new ReadableStream({
    start(controller) {
      function send(event: string, data: object) {
        try {
          controller.enqueue(enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
        } catch { /* client disconnected */ }
      }

      // Initial heartbeat so client knows the connection is live
      send("heartbeat", { ts: new Date().toISOString() });

      // Subscribe to events broadcast by the ingest endpoint
      unsubscribe = subscribeScan(scanId, (payload) => {
        try { controller.enqueue(enc.encode(payload)); }
        catch { unsubscribe?.(); }
      });

      // Keep-alive every 15 seconds
      heartbeatTimer = setInterval(() => {
        send("heartbeat", { ts: new Date().toISOString() });
      }, HEARTBEAT_MS);
    },

    cancel() {
      clearInterval(heartbeatTimer);
      unsubscribe?.();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type":      "text/event-stream",
      "Cache-Control":     "no-cache",
      "Connection":        "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
