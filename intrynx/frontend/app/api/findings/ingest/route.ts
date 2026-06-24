import { NextResponse }              from "next/server";
import { getAgent }                  from "../../../../lib/agents-store";
import { saveFindings }              from "../../../../lib/findings-store";
import { broadcastToScan }           from "../../../../lib/scan-events";
import type { LiveFinding }          from "../../../../lib/engine/types";
import { ingestFindings, isProbeSession } from "../../../../lib/probe/store";
import type { Envelope }             from "../../../../lib/probe/contracts";

// POST /api/findings/ingest — called by the probe/agent during a live scan.
export async function POST(request: Request) {
  const auth    = request.headers.get("Authorization") ?? "";
  const agentId = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  const body = await request.json().catch(() => null) as {
    scanId?: string;
    agentId?: string;
    findings?: unknown[];
    blob?: Envelope;            // new thin-probe flow: sealed findings
  } | null;

  if (!body || !body.scanId) {
    return NextResponse.json({ error: "scanId is required" }, { status: 400 });
  }

  // New thin-probe flow: decrypt the sealed envelope to findings.
  let findings: LiveFinding[];
  if (body.blob) {
    if (!isProbeSession(agentId)) {
      return NextResponse.json({ error: "Unauthorized — unknown session" }, { status: 401 });
    }
    try {
      findings = ingestFindings(agentId, body.blob) as LiveFinding[];
    } catch {
      return NextResponse.json({ error: "decrypt failed" }, { status: 400 });
    }
  } else {
    // Legacy plaintext flow.
    if (!agentId || !getAgent(agentId)) {
      return NextResponse.json({ error: "Unauthorized — unknown agentId" }, { status: 401 });
    }
    if (!Array.isArray(body.findings) || body.findings.length === 0) {
      return NextResponse.json({ error: "scanId and non-empty findings[] are required" }, { status: 400 });
    }
    findings = body.findings as LiveFinding[];
  }
  if (findings.length === 0) {
    return NextResponse.json({ saved: 0, duplicates: 0 });
  }
  const before   = findings.length;
  const saved    = saveFindings(findings, body.scanId);
  const dups     = before - saved;

  // Broadcast each new finding to any live SSE subscribers for this scan
  for (const f of findings) {
    broadcastToScan(body.scanId, "finding", f);
  }

  return NextResponse.json({ saved, duplicates: dups });
}
