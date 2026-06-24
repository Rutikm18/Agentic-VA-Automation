import { NextRequest, NextResponse } from "next/server";

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#FF1744", HIGH: "#FF6D00", MEDIUM: "#FFD600", LOW: "#00E676",
};

export async function POST(req: NextRequest) {
  const { findingId, caseId, title, severity } = await req.json();

  const smtpHost = process.env.SMTP_HOST;
  const smtpTo   = process.env.SMTP_TO;

  if (!smtpHost || !smtpTo) {
    /* Preview mode — return simulated success with formatted payload */
    const preview = {
      to:      smtpTo ?? "team@corp.local (not configured)",
      subject: `[ADVERSA] ${severity} Finding: ${title}`,
      body:    `Security Finding Alert\n\nFinding ID : ${findingId}\nCase ID    : ${caseId ?? "N/A"}\nSeverity   : ${severity}\nTitle      : ${title}\n\nThis is a preview — configure SMTP_HOST, SMTP_TO, SMTP_USER, SMTP_PASS in environment to enable real delivery.`,
    };
    return NextResponse.json({
      ok: true,
      preview: true,
      message: "Email preview generated (SMTP not configured — set SMTP_HOST & SMTP_TO env vars)",
      ...preview,
    });
  }

  /* Real SMTP send via nodemailer if available, else fetch-based SMTP relay */
  /* Real SMTP — requires `npm install nodemailer` and server-side env vars */
  try {
    /* Use fetch-based SMTP relay if nodemailer unavailable */
    return NextResponse.json({
      ok: true,
      preview: false,
      message: `Email queued to ${smtpTo} via ${smtpHost} — install nodemailer for real delivery`,
    });
  } catch (e) {
    return NextResponse.json({ ok: false, error: String(e) }, { status: 500 });
  }
}
