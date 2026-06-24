import { NextRequest, NextResponse } from "next/server";

const JIRA_PRIORITY: Record<string, string> = {
  CRITICAL: "Highest", HIGH: "High", MEDIUM: "Medium", LOW: "Low",
};

export async function POST(req: NextRequest) {
  const { findingId, caseId, title, severity } = await req.json();

  const jiraUrl   = process.env.JIRA_URL;
  const jiraEmail = process.env.JIRA_EMAIL;
  const jiraToken = process.env.JIRA_API_TOKEN;
  const projectKey= process.env.JIRA_PROJECT_KEY ?? "SEC";

  const issuePayload = {
    fields: {
      project: { key: projectKey },
      summary: `[ADVERSA][${severity}] ${title}`,
      description: {
        type: "doc",
        version: 1,
        content: [
          {
            type: "paragraph",
            content: [
              { type: "text", text: `Finding ID: ${findingId}\nCase ID: ${caseId ?? "N/A"}\nSeverity: ${severity}\n\nRefer to ADVERSA platform for full evidence, remediation steps, and compliance mapping.` },
            ],
          },
        ],
      },
      issuetype:  { name: "Bug" },
      priority:   { name: JIRA_PRIORITY[severity] ?? "Medium" },
      labels:     ["adversa", "security", `severity-${severity.toLowerCase()}`, "vapt"],
    },
  };

  if (!jiraUrl || !jiraEmail || !jiraToken) {
    const fakeKey = `${projectKey}-${Math.floor(1000 + Math.random() * 9000)}`;
    return NextResponse.json({
      ok: true,
      preview: true,
      key: fakeKey,
      url: `https://your-org.atlassian.net/browse/${fakeKey}`,
      message: "Jira preview generated (JIRA_URL / JIRA_EMAIL / JIRA_API_TOKEN not configured)",
      payload: issuePayload,
    });
  }

  try {
    const res = await fetch(`${jiraUrl}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${Buffer.from(`${jiraEmail}:${jiraToken}`).toString("base64")}`,
      },
      body: JSON.stringify(issuePayload),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Jira ${res.status}: ${text}`);
    }

    const data = await res.json();
    return NextResponse.json({
      ok: true,
      key: data.key,
      url: `${jiraUrl}/browse/${data.key}`,
      message: `Jira issue ${data.key} created`,
    });
  } catch (e) {
    return NextResponse.json({ ok: false, error: String(e) }, { status: 500 });
  }
}
