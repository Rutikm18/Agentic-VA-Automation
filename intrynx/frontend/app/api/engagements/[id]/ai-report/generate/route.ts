import { NextResponse } from "next/server";
import {
  aiReportStore, llmReportGenerator, hallucinationGuard,
  type ReportSection, type FindingInput, type AssetInput,
} from "../../../../../../lib/ai-engine";

const DEMO_ENGAGEMENT = {
  name: "ACME Corp — Q2 VAPT",
  totalFindings: { CRITICAL: 3, HIGH: 4, MEDIUM: 5, LOW: 2 },
  attackPathCount: 4,
  detectionCoverage: 53,
  topRisks: [
    "Domain Admin compromise via Kerberoasting + unconstrained delegation",
    "SMB relay attack — 4 hosts without SMB signing",
    "AD CS ESC1/ESC8 — certificate-based domain takeover",
  ],
};

const DEMO_FINDING: FindingInput = {
  id: "VAPT-CRIT-002", title: "Kerberoastable Service Account (svc_backup)",
  severity: "CRITICAL", cvss: 8.8, cveId: undefined,
  affectedHost: "10.0.1.20", exploitValidated: true,
  description: "Service account svc_backup uses RC4-HMAC Kerberos encryption, enabling offline hash cracking.",
  mitreTechnique: "T1558.003 — Kerberoasting",
  evidence: "TGS hash captured: $krb5tgs$23$*svc_backup$corp.local$...[truncated]",
};

const DEMO_ASSET: AssetInput = {
  id: "svc-sql", label: "SVC-SQL", criticality: "CRITICAL",
  internetExposed: false, zone: "CORP", lateralReachableCount: 12, daysSinceLastPatch: 180,
};

// POST /engagements/{id}/ai-report/generate
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await request.json().catch(() => ({}));
  const sections: ReportSection[] = body.sections ?? ["executive_summary", "technical_finding", "remediation"];
  const apiKey = process.env.ANTHROPIC_API_KEY;

  const job = aiReportStore.createJob(id, sections);
  aiReportStore.updateJob(job.jobId, { status: "running", progress: 5 });

  const sectionCount = sections.length;
  let completed = 0;

  const outputs = await Promise.allSettled(
    sections.map(async (section) => {
      let output = "";
      const hashInput = `${id}:${section}:${Date.now()}`;

      if (section === "executive_summary") {
        output = await llmReportGenerator.generateExecutiveSummary(DEMO_ENGAGEMENT, apiKey);
      } else if (section === "technical_finding") {
        output = await llmReportGenerator.generateTechnicalFinding(DEMO_FINDING, DEMO_ASSET, DEMO_FINDING.evidence ?? "", apiKey);
      } else if (section === "remediation") {
        output = await llmReportGenerator.generateRemediationSteps(DEMO_FINDING, apiKey);
      } else if (section === "sigma_explanation") {
        output = await llmReportGenerator.generateSigmaExplanation(
          "title: Kerberoasting Detection\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4769\n    TicketEncryptionType: '0x17'\n  condition: selection",
          "T1558.003 — Kerberoasting",
          apiKey
        );
      }

      const guardResult = hallucinationGuard.validate(output, {
        cveIds: DEMO_FINDING.cveId ? [DEMO_FINDING.cveId] : [],
        cvssScores: { [DEMO_FINDING.title]: DEMO_FINDING.cvss },
      });

      const saved = aiReportStore.saveOutput({
        engagementId: id, section,
        promptHash: aiReportStore.hashPrompt(hashInput),
        model: "claude-sonnet-4-20250514",
        prompt: `[${section}] ${id}`,
        output, reviewStatus: "pending",
        hallucinationCheck: guardResult,
      });

      completed++;
      aiReportStore.updateJob(job.jobId, {
        progress: Math.round((completed / sectionCount) * 100),
        completedSections: [...(aiReportStore.getJob(job.jobId)?.completedSections ?? []), section],
      });

      return saved;
    })
  );

  const allOk = outputs.every((r) => r.status === "fulfilled");
  aiReportStore.updateJob(job.jobId, {
    status: allOk ? "completed" : "failed",
    completedAt: new Date().toISOString(),
    progress: 100,
  });

  return NextResponse.json({ jobId: job.jobId, status: allOk ? "completed" : "failed", sections }, { status: 202 });
}
