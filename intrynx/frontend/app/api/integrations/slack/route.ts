import { NextRequest, NextResponse } from "next/server";

const SEV_HEX: Record<string, string> = {
  CRITICAL: "#FF1744", HIGH: "#FF6D00", MEDIUM: "#FFD600", LOW: "#00E676",
};

export async function POST(req: NextRequest) {
  const { findingId, caseId, title, severity } = await req.json();
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;

  const blocks = {
    attachments: [
      {
        color: SEV_HEX[severity] ?? "#888888",
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: `🔴 ADVERSA: ${severity} Finding`, emoji: true },
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Finding ID*\n${findingId}` },
              { type: "mrkdwn", text: `*Case ID*\n${caseId ?? "N/A"}` },
              { type: "mrkdwn", text: `*Severity*\n${severity}` },
              { type: "mrkdwn", text: `*Title*\n${title}` },
            ],
          },
          {
            type: "context",
            elements: [
              { type: "mrkdwn", text: `Sent by *ADVERSA Platform* · ${new Date().toUTCString()}` },
            ],
          },
        ],
      },
    ],
  };

  if (!webhookUrl) {
    return NextResponse.json({
      ok: true,
      preview: true,
      message: "Slack preview generated (SLACK_WEBHOOK_URL not configured)",
      payload: blocks,
    });
  }

  try {
    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(blocks),
    });
    if (!res.ok) throw new Error(`Slack returned ${res.status}: ${await res.text()}`);
    return NextResponse.json({ ok: true, message: "Slack notification sent" });
  } catch (e) {
    return NextResponse.json({ ok: false, error: String(e) }, { status: 500 });
  }
}
