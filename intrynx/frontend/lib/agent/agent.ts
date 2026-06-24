/**
 * The autonomous engagement agent.
 *
 * Drives Claude via the tool-use API. Each iteration:
 *   1. Claude proposes a tool call (or final answer)
 *   2. Safety envelope classifies risk
 *   3. Approval gate (if needed for this rung)
 *   4. Execute against engagement state
 *   5. Feed result back to Claude
 *   6. Repeat until Claude calls `summarize_and_stop` or budget exhausted
 */
import Anthropic from '@anthropic-ai/sdk';
import { TOOL_REGISTRY, type AgentState, type ToolDef, type Risk, persistAgentFindings } from './tools';
import type { ScanCallbacks, DiscoveredHost } from '../engine/types';

const MODEL = 'claude-sonnet-4-6';

export type Rung = 1 | 2 | 3;

const RUNG_LABELS: Record<Rung, string> = {
  1: 'Co-pilot (you approve every tool call)',
  2: 'Bounded (auto-runs READ_ONLY + ACTIVE; you approve STATE_CHANGE)',
  3: 'Engagement autonomous (auto-runs everything except DESTRUCTIVE)',
};

export interface AgentOpts {
  /** Targets the operator picked (CIDRs, hosts, etc.) */
  scope:        string[];
  /** Origin of the scope (for context in the prompt) */
  scopeLabel:   string;
  /** Autonomy rung — 1 / 2 / 3 */
  rung:         Rung;
  /** Maximum tool calls the agent can make before forced stop */
  actionBudget: number;
  /** Engagement to tag findings against (optional) */
  engagementId?: string;
}

export interface AgentDeps {
  /** Output sink for scanner progress lines */
  cb: ScanCallbacks;
  /** UI for showing the proposed action + risk + approval prompt */
  ui: {
    onAgentThinking: (text: string)                                      => void;
    onProposal:      (tool: string, input: object, risk: Risk)           => void;
    requestApproval: (tool: string, input: object, risk: Risk)           => Promise<boolean>;
    onResult:        (tool: string, ok: boolean, summary: string)        => void;
    onFinalSummary:  (reason: string, state: AgentState)                 => void;
    onError:         (message: string)                                   => void;
  };
}

// ── Safety envelope ──────────────────────────────────────────────
export function requiresApproval(risk: Risk, rung: Rung): boolean {
  if (risk === 'DESTRUCTIVE') return true;       // always blocked downstream regardless
  if (rung === 1) return true;                    // co-pilot: approve everything
  if (rung === 2) return risk === 'STATE_CHANGE'; // bounded: approve state changes
  if (rung === 3) return false;                   // engagement-autonomous: no per-call approval
  return true;
}

export function isBlocked(risk: Risk): boolean {
  return risk === 'DESTRUCTIVE';
}

// ── Tool-use schema generation for Claude ───────────────────────
function toAnthropicTool(t: ToolDef): Anthropic.Tool {
  return {
    name:         t.name,
    description:  t.description,
    input_schema: t.schema as unknown as Anthropic.Tool['input_schema'],
  };
}

const SYSTEM = `You are ADVERSA, an autonomous network penetration testing agent. You drive a real engagement by calling tools that execute scans against a target network.

Your goals, in order:
1. Discover live hosts in scope
2. Identify open ports and services
3. Run service-specific enumeration on what's found
4. Run vulnerability checks (CVE / TLS / SSH) on the discovered services
5. Validate or dismiss findings based on evidence
6. Stop and summarize when you've made meaningful progress or no productive action remains

Operating rules:
- Use query_state often to see what you have. Plan before each tool call.
- Be efficient. Don't repeat tools that have already produced the data you need.
- Each call to a real scanner takes seconds to minutes. You have a finite action budget.
- After every 3–4 tool calls, take stock with query_state and reflect on what's worth doing next.
- When you have enough information, call summarize_and_stop with a clear reason.
- Never invent findings or hosts. Only act on what tool outputs actually report.
- You are operating against a network where the human operator has authorized scanning. Stay in scope.`;

// ── Agent loop ───────────────────────────────────────────────────
export async function runAutonomousEngagement(opts: AgentOpts, deps: AgentDeps): Promise<AgentState> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    deps.ui.onError('ANTHROPIC_API_KEY is not set. Autonomous mode requires it.');
    return { hosts: [], findings: [], log: [], done: true, doneReason: 'no API key' };
  }

  const ai = new Anthropic({ apiKey });
  const state: AgentState = { hosts: [], findings: [], log: [], done: false };
  const tools = TOOL_REGISTRY.map(toAnthropicTool);

  const initialUserMessage = `Begin engagement.

Scope:        ${opts.scope.join(', ')}
Scope origin: ${opts.scopeLabel}
Autonomy:     Rung ${opts.rung} — ${RUNG_LABELS[opts.rung]}
Action budget: ${opts.actionBudget} tool calls

What's your first move?`;

  const messages: Anthropic.MessageParam[] = [
    { role: 'user', content: initialUserMessage },
  ];

  let actionsUsed = 0;
  let blockedCount = 0;

  while (!state.done && actionsUsed < opts.actionBudget) {
    let response: Anthropic.Message;
    try {
      response = await ai.messages.create({
        model:      MODEL,
        max_tokens: 4096,
        system:     SYSTEM,
        tools,
        messages,
      });
    } catch (e) {
      deps.ui.onError(`LLM call failed: ${e instanceof Error ? e.message : String(e)}`);
      break;
    }

    // Collect Claude's text + tool calls
    const toolUses: Anthropic.ToolUseBlock[] = [];
    for (const block of response.content) {
      if (block.type === 'text' && block.text.trim()) {
        deps.ui.onAgentThinking(block.text.trim());
      }
      if (block.type === 'tool_use') {
        toolUses.push(block);
      }
    }

    // No tool calls → Claude is done
    if (toolUses.length === 0) {
      state.done = true;
      state.doneReason = 'Claude returned final answer without tool call';
      break;
    }

    // Add Claude's response to history (the rules require this exact echo)
    messages.push({ role: 'assistant', content: response.content });

    // Execute each tool call, collecting tool_result blocks
    const toolResults: Anthropic.ToolResultBlockParam[] = [];
    for (const use of toolUses) {
      actionsUsed++;
      const def = TOOL_REGISTRY.find((t) => t.name === use.name);
      if (!def) {
        toolResults.push({
          type:       'tool_result',
          tool_use_id: use.id,
          content:    `Error: unknown tool ${use.name}`,
          is_error:   true,
        });
        continue;
      }

      deps.ui.onProposal(def.name, use.input as object, def.risk);

      if (isBlocked(def.risk)) {
        blockedCount++;
        toolResults.push({
          type:       'tool_result',
          tool_use_id: use.id,
          content:    `Blocked: ${def.name} classified as DESTRUCTIVE. Not executed.`,
          is_error:   true,
        });
        continue;
      }

      if (requiresApproval(def.risk, opts.rung)) {
        const ok = await deps.ui.requestApproval(def.name, use.input as object, def.risk);
        if (!ok) {
          toolResults.push({
            type:       'tool_result',
            tool_use_id: use.id,
            content:    `User declined to run ${def.name}.`,
            is_error:   false,
          });
          continue;
        }
      }

      try {
        const result = await def.execute(use.input as Record<string, unknown>, state, deps.cb);
        state.log.push({ tool: def.name, input: use.input as object, result: result.slice(0, 500), ts: new Date().toISOString() });
        deps.ui.onResult(def.name, true, result.slice(0, 200));
        toolResults.push({
          type:       'tool_result',
          tool_use_id: use.id,
          content:    result,
          is_error:   false,
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        deps.ui.onResult(def.name, false, msg);
        toolResults.push({
          type:       'tool_result',
          tool_use_id: use.id,
          content:    `Error executing ${def.name}: ${msg}`,
          is_error:   true,
        });
      }
    }

    // Feed tool results back to Claude
    messages.push({ role: 'user', content: toolResults });

    // Safety check — if the agent has spammed blocked actions, stop
    if (blockedCount >= 3) {
      state.done = true;
      state.doneReason = 'Stopped — 3 destructive tool calls blocked';
      break;
    }
  }

  if (actionsUsed >= opts.actionBudget && !state.done) {
    state.done = true;
    state.doneReason = `Action budget exhausted (${opts.actionBudget} calls)`;
  }

  // Persist findings
  if (state.findings.length > 0) {
    const saved = persistAgentFindings(state, opts.engagementId);
    deps.ui.onFinalSummary(state.doneReason ?? 'done', state);
    deps.ui.onAgentThinking(`Persisted ${saved} new finding(s) to data/findings.json`);
  } else {
    deps.ui.onFinalSummary(state.doneReason ?? 'done', state);
  }

  return state;
}
