import { NextRequest, NextResponse } from "next/server";
import Anthropic                     from "@anthropic-ai/sdk";
import { getAllFindings }             from "../../../lib/findings-store";

const BRAIN_SYSTEM_BASE = `You are a senior penetration tester and red team operator.
You are working inside ADVERSA, an AI-powered VAPT platform.
You provide tactical advice on exploitation paths, credential attacks, lateral movement, and remediation prioritization.
Never provide advice outside of authorized, in-scope testing.
Be concise and specific — operators need actionable guidance, not general descriptions.`;

// POST /api/brain — AI Brain chat with optional engagement context
export async function POST(req: NextRequest) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "ANTHROPIC_API_KEY not configured" },
      { status: 503 },
    );
  }

  const body = await req.json().catch(() => null) as {
    messages?: { role: string; content: string }[];
    engagementId?: string;
    stream?: boolean;
  } | null;

  if (!body || !Array.isArray(body.messages) || body.messages.length === 0) {
    return NextResponse.json({ error: "messages[] is required" }, { status: 400 });
  }

  // Build system context, optionally enriched with engagement findings
  let systemContext = BRAIN_SYSTEM_BASE;
  if (body.engagementId) {
    const findings = getAllFindings()
      .filter((f) => f.engagementId === body.engagementId)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
      .slice(0, 20);

    if (findings.length > 0) {
      const counts = findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1;
        return acc;
      }, {});
      const summary = Object.entries(counts).map(([s, n]) => `${s}: ${n}`).join(", ");
      systemContext += `\n\nCurrent engagement has ${findings.length} findings — ${summary}.\nTop findings:\n` +
        findings.slice(0, 5).map((f) => `- [${f.severity}] ${f.host}: ${f.title}`).join("\n");
    }
  }

  const client = new Anthropic({ apiKey });

  // Streaming response
  if (body.stream) {
    const encoder = new TextEncoder();
    const stream  = new ReadableStream({
      async start(controller) {
        try {
          const msgStream = client.messages.stream({
            model:      "claude-sonnet-4-6",
            max_tokens: 2048,
            system:     systemContext,
            messages:   body.messages as Anthropic.MessageParam[],
          });

          for await (const chunk of msgStream) {
            if (chunk.type === "content_block_delta" && chunk.delta.type === "text_delta") {
              controller.enqueue(encoder.encode(`data: ${JSON.stringify({ content: chunk.delta.text })}\n\n`));
            }
          }
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        } catch (err) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: String(err) })}\n\n`));
        } finally {
          controller.close();
        }
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type":  "text/event-stream",
        "Cache-Control": "no-cache",
      },
    });
  }

  // Non-streaming response
  try {
    const msg = await client.messages.create({
      model:      "claude-sonnet-4-6",
      max_tokens: 2048,
      system:     systemContext,
      messages:   body.messages as Anthropic.MessageParam[],
    });
    const content = (msg.content[0] as { text: string }).text;
    return NextResponse.json({ content });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
