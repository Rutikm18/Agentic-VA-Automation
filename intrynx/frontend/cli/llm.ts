/**
 * LLM commentary woven into the CLI scan flow.
 * Calls Claude for: stage narration, inline finding context, attack path, and chat.
 */
import Anthropic               from '@anthropic-ai/sdk';
import type { LiveFinding, DiscoveredHost, ScanSummary } from '../lib/engine/types';

const MODEL = 'claude-sonnet-4-6';

function client(): Anthropic | null {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return null;
  return new Anthropic({ apiKey: key });
}

const SYSTEM = `You are ADVERSA, an AI penetration testing assistant embedded in a CLI tool.
You provide concise, actionable security analysis for operators running authorized VAPT engagements.
Responses are shown directly in the terminal — be terse, specific, and technically accurate.
Never fabricate CVEs or exploits. Use plain text only (no markdown, no headers, no bullet points unless listing items).`;

// ── Stage commentary ─────────────────────────────────────────────
export async function commentOnStage(
  stage:    string,
  summary:  string,
  hosts:    DiscoveredHost[],
  findings: LiveFinding[],
): Promise<string | null> {
  const ai = client();
  if (!ai) return null;

  const hostSummary = hosts.slice(0, 5).map(
    (h) => `${h.ip} [${h.ports.join(',')}]${h.os ? ` OS:${h.os}` : ''}`,
  ).join('; ');

  const prompt = `Stage "${stage}" just completed: ${summary}.
${hosts.length > 0 ? `Hosts so far: ${hostSummary}` : ''}
${findings.length > 0 ? `Findings so far: ${findings.length} total, ${findings.filter(f => f.severity === 'CRITICAL').length} critical, ${findings.filter(f => f.severity === 'HIGH').length} high.` : ''}
In 1-2 sentences, narrate what this stage revealed and what it means for the engagement.`;

  try {
    const msg = await ai.messages.create({
      model:      MODEL,
      max_tokens: 120,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: prompt }],
    });
    return (msg.content[0] as { text: string }).text.trim();
  } catch {
    return null;
  }
}

// ── Inline finding context (batched per stage) ───────────────────
export async function explainFindings(findings: LiveFinding[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (findings.length === 0) return out;
  const ai = client();
  if (!ai) return out;

  const list = findings.slice(0, 10).map(
    (f, i) => `${i + 1}. [${f.severity}] ${f.host}${f.port ? `:${f.port}` : ''} — ${f.title}${f.cveIds?.length ? ` (${f.cveIds[0]})` : ''}`,
  ).join('\n');

  const prompt = `For each finding below, write a single sentence: what it means and whether it is immediately exploitable.
Format: N. <one sentence>
Findings:\n${list}`;

  try {
    const msg = await ai.messages.create({
      model:      MODEL,
      max_tokens: 400,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: prompt }],
    });
    const text = (msg.content[0] as { text: string }).text.trim();
    const lines = text.split('\n');
    for (const line of lines) {
      const m = line.match(/^(\d+)\.\s+(.+)/);
      if (m) {
        const idx = parseInt(m[1]) - 1;
        if (idx >= 0 && idx < findings.length) {
          out.set(findings[idx].id, m[2].trim());
        }
      }
    }
  } catch { /* non-fatal */ }

  return out;
}

// ── Attack path suggestion (after all stages) ────────────────────
export async function suggestAttackPath(
  hosts:    DiscoveredHost[],
  findings: LiveFinding[],
  summary:  ScanSummary,
): Promise<string | null> {
  const ai = client();
  if (!ai) return null;
  if (findings.length === 0) return null;

  const top = findings
    .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 8)
    .map((f) => `- [${f.severity}] ${f.host}${f.port ? `:${f.port}` : ''}: ${f.title}${f.cveIds?.[0] ? ` (${f.cveIds[0]})` : ''}`)
    .join('\n');

  const prompt = `Network VAPT scan completed.
Hosts: ${summary.hostsScanned}, Findings: ${summary.totalFindings} (${summary.bySeverity.CRITICAL} critical, ${summary.bySeverity.HIGH} high).
Top findings:\n${top}

Recommend the 2-3 most promising attack paths in order of exploitability. Be specific about which host/port/CVE to start with and why.`;

  try {
    const msg = await ai.messages.create({
      model:      MODEL,
      max_tokens: 350,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: prompt }],
    });
    return (msg.content[0] as { text: string }).text.trim();
  } catch {
    return null;
  }
}

// ── Batch validation (Claude reviews each finding's evidence) ────
export interface ValidationVerdict {
  findingId:   string;
  verdict:     'LIKELY_TRUE_POSITIVE' | 'LIKELY_FALSE_POSITIVE' | 'NEEDS_HUMAN_REVIEW';
  confidence:  'HIGH' | 'MEDIUM' | 'LOW';
  reasoning:   string;
}

/**
 * Ask Claude to validate findings based on their evidence. Returns one verdict
 * per finding. Batched to keep token cost reasonable — splits into groups of 8.
 */
export async function validateFindings(findings: LiveFinding[]): Promise<Map<string, ValidationVerdict>> {
  const out = new Map<string, ValidationVerdict>();
  const ai = client();
  if (!ai || findings.length === 0) return out;

  const BATCH = 8;
  for (let i = 0; i < findings.length; i += BATCH) {
    const batch = findings.slice(i, i + BATCH);
    const list = batch.map((f, idx) => {
      const evidenceText = f.evidence.map((e) => `${e.label}: ${e.content.slice(0, 300)}`).join('\n');
      return `${idx + 1}. [${f.severity}] ${f.host}${f.port ? ':' + f.port : ''} — ${f.title}
   id: ${f.id}
   source: ${f.source}${f.cveIds?.length ? '  cve: ' + f.cveIds.join(',') : ''}
   evidence:
${evidenceText.split('\n').map((l) => '     ' + l).join('\n')}`;
    }).join('\n\n');

    const prompt = `You are validating pentest findings. For each finding below, judge whether the evidence supports it as a likely true positive, a likely false positive, or whether it needs human review.

Respond ONLY with JSON in this exact shape (no markdown, no preamble):
{"verdicts":[
  {"index":1,"verdict":"LIKELY_TRUE_POSITIVE","confidence":"HIGH","reasoning":"one short sentence"},
  ...
]}

Verdict choices: LIKELY_TRUE_POSITIVE, LIKELY_FALSE_POSITIVE, NEEDS_HUMAN_REVIEW.
Confidence: HIGH, MEDIUM, LOW.

Findings:
${list}`;

    try {
      const msg = await ai.messages.create({
        model:      MODEL,
        max_tokens: 1500,
        system:     SYSTEM,
        messages:   [{ role: 'user', content: prompt }],
      });
      const text = (msg.content[0] as { text: string }).text.trim();
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) continue;
      const parsed = JSON.parse(jsonMatch[0]) as { verdicts: Array<{ index: number; verdict: string; confidence: string; reasoning: string }> };
      for (const v of parsed.verdicts ?? []) {
        const f = batch[v.index - 1];
        if (!f) continue;
        const verdict = (['LIKELY_TRUE_POSITIVE', 'LIKELY_FALSE_POSITIVE', 'NEEDS_HUMAN_REVIEW'].includes(v.verdict)
          ? v.verdict
          : 'NEEDS_HUMAN_REVIEW') as ValidationVerdict['verdict'];
        const confidence = (['HIGH', 'MEDIUM', 'LOW'].includes(v.confidence)
          ? v.confidence
          : 'LOW') as ValidationVerdict['confidence'];
        out.set(f.id, {
          findingId: f.id,
          verdict,
          confidence,
          reasoning: v.reasoning?.slice(0, 200) ?? '',
        });
      }
    } catch { /* skip this batch on failure */ }
  }

  return out;
}

// ── Phase recommendation — AI suggests the next move ─────────────
export type PhaseId = 'port_scan' | 'service_detect' | 'enumerate' | 'vuln_assess' | 'validate' | 'exploit' | 'report' | 'stop';

export interface PhaseRecommendation {
  recommended:    PhaseId;
  reasoning:      string;
  alternative?:   PhaseId;
}

const PHASE_LABELS: Record<PhaseId, string> = {
  port_scan:      'Port scan',
  service_detect: 'Service / version detection',
  enumerate:      'Service-specific enumeration (SMB/SNMP/LDAP/RPC/RDP/DB)',
  vuln_assess:    'Vulnerability assessment (CVE / TLS / SSH)',
  validate:       'Validate existing findings',
  exploit:        'Attempt exploitation of verified findings',
  report:         'Generate AI pentest report',
  stop:           'Stop and save state',
};

export async function recommendNextPhase(
  hosts:    DiscoveredHost[],
  findings: LiveFinding[],
  availableNext: PhaseId[],
): Promise<PhaseRecommendation | null> {
  const ai = client();
  if (!ai) return null;

  const verifiedCount = findings.filter((f) => f.status === 'VERIFIED').length;
  const openCritHigh = findings.filter((f) => f.status === 'OPEN' && (f.severity === 'CRITICAL' || f.severity === 'HIGH')).length;
  const hostSummary  = hosts.slice(0, 5).map(
    (h) => `${h.ip} [${h.ports.slice(0, 8).join(',')}${h.ports.length > 8 ? '+…' : ''}]`,
  ).join('; ');

  const prompt = `You are advising a pentest operator on the next move.

Current engagement state:
- Hosts discovered: ${hosts.length}${hostSummary ? '\n  Sample: ' + hostSummary : ''}
- Findings so far: ${findings.length} total, ${openCritHigh} open CRITICAL/HIGH, ${verifiedCount} VERIFIED
- Available next phases: ${availableNext.map((p) => `${p} (${PHASE_LABELS[p]})`).join(', ')}

Pick the SINGLE highest-value next phase from the available list. Respond ONLY with JSON (no markdown):
{"recommended":"<phase_id>","reasoning":"one short sentence","alternative":"<phase_id or null>"}`;

  try {
    const msg = await ai.messages.create({
      model:      MODEL,
      max_tokens: 200,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: prompt }],
    });
    const text = (msg.content[0] as { text: string }).text.trim();
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return null;
    const parsed = JSON.parse(m[0]) as PhaseRecommendation;
    if (!availableNext.includes(parsed.recommended)) return null;
    return parsed;
  } catch {
    return null;
  }
}

// ── Exploit planner — generate exploit command + risk class ──────
export interface ExploitPlan {
  command:           string;
  explanation:       string;
  tool:              'metasploit' | 'manual' | 'curl' | 'nuclei' | 'native';
  module:            string;
  risk:              'READ_ONLY' | 'ACTIVE' | 'STATE_CHANGE' | 'DESTRUCTIVE';
  verificationOnly:  boolean;
  successIndicator:  string;
  failureIndicator:  string;
  requiresApproval:  boolean;
  reasonNeedsApproval?: string;
}

export async function planExploit(finding: LiveFinding): Promise<ExploitPlan | null> {
  const ai = client();
  if (!ai) return null;

  const prompt = `You are building a verification-only exploit plan for a confirmed pentest finding. Default to the safest tool that proves the vulnerability is exploitable.

Finding:
- ${finding.severity}  ${finding.host}${finding.port ? ':' + finding.port : ''}  ${finding.title}
- Source: ${finding.source}
- CVEs: ${finding.cveIds?.join(', ') || '(none)'}
- Evidence: ${finding.evidence.map((e) => e.content.slice(0, 200)).join(' | ')}

Strict rules:
- NEVER generate destructive commands (rm, format, wipe, encrypt, denial-of-service).
- Prefer verification-only checks (e.g., banner grab, version readback, single curl).
- Default to verification_only: true.
- Risk classification: READ_ONLY = passive read, ACTIVE = probe/exploit attempt, STATE_CHANGE = modifies target, DESTRUCTIVE = harmful (never allowed).
- Set requires_approval: true for ANY risk above READ_ONLY.

Respond ONLY with JSON (no markdown):
{
  "command":"<the exact shell command>",
  "explanation":"<one sentence: what this does>",
  "tool":"metasploit|manual|curl|nuclei|native",
  "module":"<module/script name or 'none'>",
  "risk":"READ_ONLY|ACTIVE|STATE_CHANGE|DESTRUCTIVE",
  "verification_only":true|false,
  "success_indicator":"<what output proves success>",
  "failure_indicator":"<what output proves the target is safe>",
  "requires_approval":true|false,
  "reason_needs_approval":"<sentence or null>"
}`;

  try {
    const msg = await ai.messages.create({
      model:      MODEL,
      max_tokens: 700,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: prompt }],
    });
    const text = (msg.content[0] as { text: string }).text.trim();
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return null;
    const raw = JSON.parse(m[0]) as Record<string, unknown>;
    return {
      command:          String(raw.command ?? ''),
      explanation:      String(raw.explanation ?? ''),
      tool:             (raw.tool ?? 'manual') as ExploitPlan['tool'],
      module:           String(raw.module ?? ''),
      risk:             (raw.risk ?? 'ACTIVE') as ExploitPlan['risk'],
      verificationOnly: !!raw.verification_only,
      successIndicator: String(raw.success_indicator ?? ''),
      failureIndicator: String(raw.failure_indicator ?? ''),
      requiresApproval: !!raw.requires_approval,
      reasonNeedsApproval: raw.reason_needs_approval ? String(raw.reason_needs_approval) : undefined,
    };
  } catch {
    return null;
  }
}

// ── Interactive ask (streaming) ──────────────────────────────────
export async function streamAsk(
  question:      string,
  findings:      LiveFinding[],
  hosts:         DiscoveredHost[],
  onChunk:       (text: string) => void,
  history:       { role: 'user' | 'assistant'; content: string }[] = [],
): Promise<void> {
  const ai = client();
  if (!ai) {
    onChunk('ANTHROPIC_API_KEY not set — cannot use AI features.\n');
    return;
  }

  const context = findings.length > 0
    ? `Current scan context: ${findings.length} findings (${findings.filter(f => f.severity === 'CRITICAL').length} critical, ${findings.filter(f => f.severity === 'HIGH').length} high). Hosts: ${hosts.map(h => h.ip).slice(0, 10).join(', ')}.`
    : '';

  const messages: Anthropic.MessageParam[] = [
    ...history,
    { role: 'user', content: context ? `${context}\n\n${question}` : question },
  ];

  const stream = ai.messages.stream({
    model:      MODEL,
    max_tokens: 1024,
    system:     SYSTEM,
    messages,
  });

  for await (const chunk of stream) {
    if (chunk.type === 'content_block_delta' && chunk.delta.type === 'text_delta') {
      onChunk(chunk.delta.text);
    }
  }
}
