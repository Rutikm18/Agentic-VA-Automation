import { NextRequest, NextResponse }          from "next/server";
import jwt                                    from "jsonwebtoken";
import { parseTargets }                       from "../../../../lib/target-parser";
import { createJob }                          from "../../../../lib/job-store";
import { withAuth, type AuthContext }         from "../../../../lib/auth-middleware";
import { isScopeAllowed }                     from "../../../../lib/permissions-store";

// POST /api/scans/start — authenticated; validates scope permission
export const POST = withAuth(async (req: NextRequest, ctx: AuthContext) => {
  const body = await req.json().catch(() => null) as {
    targets?: string[];
    profile?: string;
    stealth?: number;
    tools?: string[];
    engagementId?: string;
    agentId?: string;
  } | null;

  if (!body || !Array.isArray(body.targets) || body.targets.length === 0) {
    return NextResponse.json({ error: "targets[] is required" }, { status: 400 });
  }

  // Validate targets
  let targets: string[];
  try {
    targets = parseTargets(body.targets);
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "Invalid targets" }, { status: 400 });
  }

  // Scope permission check per target
  const denied = targets.filter((t) => !isScopeAllowed(ctx.email, t));
  if (denied.length > 0) {
    return NextResponse.json(
      { error: `Targets out of your permitted scope: ${denied.join(', ')}. Ask an admin to expand your scope.` },
      { status: 403 },
    );
  }

  const secret = process.env.SCOPE_SECRET ?? "change-me-in-production";
  const scanId = `SCAN-${Date.now()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
  const now    = Math.floor(Date.now() / 1000);

  const scopeToken = jwt.sign(
    {
      scanId,
      targets,
      operatorEmail: ctx.email,
      notBefore:     now,
      notAfter:      now + 86_400,
    },
    secret,
    { expiresIn: "24h" },
  );

  const job = createJob(
    "scan",
    {
      scanId,
      targets,
      profile:       body.profile ?? "standard",
      stealth:       body.stealth ?? 5,
      tools:         body.tools ?? ["naabu", "nmap", "nuclei"],
      engagementId:  body.engagementId,
      operatorEmail: ctx.email,
    },
    scopeToken,
    body.agentId,
  );

  return NextResponse.json({ scanId, jobId: job.id, scopeToken });
});
