import { Command }                    from "commander";
import { readFileSync, existsSync }    from "fs";
import { runScan }                     from "../../lib/engine/scanner";
import type { ScanOptions, ScanCallbacks, LiveFinding, DiscoveredHost } from "../../lib/engine/types";
import * as out                        from "../ui/output";
import { requireAuth }                 from "../auth";
import * as llm                        from "../llm";

const PROFILE_TOOLS: Record<string, ('naabu'|'nmap'|'nuclei'|'testssl')[]> = {
  fast:     ['naabu', 'nuclei'],
  standard: ['naabu', 'nmap', 'nuclei'],
  deep:     ['naabu', 'nmap', 'nuclei', 'testssl'],
};

const SAFE_TARGET = /^[a-zA-Z0-9.\-_/:,]+$/;

function resolveTargets(args: string[], fromFile?: string): string[] {
  const raw: string[] = [...args];
  if (fromFile) {
    if (!existsSync(fromFile)) { out.error(`File not found: ${fromFile}`); process.exit(1); }
    raw.push(...readFileSync(fromFile, "utf-8").split(/[\r\n]+/).filter(Boolean));
  }
  const targets = [...new Set(raw.map((t) => t.trim()).filter(Boolean))];
  const invalid = targets.filter((t) => !SAFE_TARGET.test(t) || t.length >= 200);
  if (invalid.length) { out.error(`Invalid target(s): ${invalid.join(", ")}`); process.exit(1); }
  if (targets.length === 0) { out.error("No targets specified."); process.exit(1); }
  return targets;
}

function printAiComment(text: string): void {
  const lines = text.split('\n');
  for (const line of lines) {
    process.stdout.write(`  \x1b[2m\x1b[36m▸\x1b[0m \x1b[2m${line}\x1b[0m\n`);
  }
}

export default async function scanCommand(targets: string[], options: Record<string, string>): Promise<void> {
  // Auth check
  const session = requireAuth();

  const profile = (["fast", "standard", "deep"].includes(options.profile ?? "") ? options.profile : "standard") as ScanOptions["profile"];
  const stealth = Math.min(9, Math.max(1, parseInt(options.stealth ?? "5", 10) || 5));
  const save    = options.save === "true" || options.save === "1";
  const noAi    = options.noAi === "true";

  let tools: ScanOptions["tools"];
  if (options.tools) {
    const valid = ["naabu", "nmap", "nuclei", "testssl"] as const;
    tools = options.tools.split(",").map((t) => t.trim()).filter((t): t is typeof valid[number] => valid.includes(t as typeof valid[number]));
    if (tools.length === 0) { out.error(`No valid tools: ${options.tools}`); process.exit(1); }
  } else {
    tools = PROFILE_TOOLS[profile];
  }

  const opts: ScanOptions = {
    targets,
    profile,
    stealth,
    tools,
    save,
    scanId: `SCAN-${Date.now()}`,
  };

  out.banner();
  out.scanHeader(targets, profile, stealth, tools);
  process.stdout.write(`  \x1b[2mOperator:\x1b[0m ${session.email}\n\n`);

  const discovered: DiscoveredHost[] = [];
  const allFindings: LiveFinding[]   = [];
  const stageFindings = new Map<string, LiveFinding[]>();
  let   currentStage  = '';

  const callbacks: ScanCallbacks = {
    onStageStart(stage) {
      currentStage = stage;
      stageFindings.set(stage, []);
      out.stageStart(stage);
    },

    async onStageComplete(stage, summary) {
      out.stageComplete(stage, summary);

      if (!noAi) {
        const comment = await llm.commentOnStage(stage, summary, discovered, allFindings);
        if (comment) printAiComment(comment);

        // Explain findings discovered in this stage
        const stageFounds = stageFindings.get(stage) ?? [];
        if (stageFounds.length > 0) {
          const contexts = await llm.explainFindings(stageFounds);
          for (const [id, ctx] of contexts) {
            const f = stageFounds.find((x) => x.id === id);
            if (f) {
              process.stdout.write(`    \x1b[2m└─ ${ctx}\x1b[0m\n`);
            }
          }
        }
      }
    },

    onHostDiscovered(host) {
      if (!discovered.find((h) => h.ip === host.ip)) discovered.push(host);
      out.hostLine(host);
    },

    onFinding(f) {
      allFindings.push(f);
      stageFindings.get(currentStage)?.push(f);
      out.findingLine(f);
    },

    onProgress(pct, msg) { out.stageProgress(pct, msg); },
    onError(stage, err)   { out.stageError(stage, err); },

    async onComplete(s) {
      out.summary(s);

      // Attack path suggestion
      if (!noAi && allFindings.length > 0) {
        process.stdout.write('\n\x1b[1;36m  AI Attack Path Analysis\x1b[0m\n');
        const path = await llm.suggestAttackPath(discovered, allFindings, s);
        if (path) {
          printAiComment(path);
        }
        process.stdout.write('\n');
      }

      if (save) {
        out.info(`Findings saved to data/findings.json`);
        out.info(`Run \`adversa findings\` to view · \`adversa ask "<question>"\` to analyze`);
      }
    },
  };

  try {
    await runScan(opts, callbacks);
  } catch (e) {
    out.error(`Scan failed: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}

export function buildScanCommand(): Command {
  const cmd = new Command("scan");
  cmd
    .description("Run a network VAPT scan against one or more targets")
    .argument("[targets...]", "IP addresses, hostnames, or CIDRs")
    .option("-f, --file <path>",     "Read targets from file (one per line)")
    .option("-p, --profile <name>",  "Scan profile: fast | standard | deep", "standard")
    .option("-s, --stealth <level>", "Stealth level 1–9", "5")
    .option("--save",                "Persist findings to data/findings.json")
    .option("--tools <list>",        "Comma-separated: naabu,nmap,nuclei,testssl")
    .option("--no-ai",               "Disable LLM commentary")
    .action(async (targetArgs: string[], opts: {
      file?: string; profile: string; stealth: string;
      save?: boolean; tools?: string; noAi?: boolean;
    }) => {
      const targets = resolveTargets(targetArgs, opts.file);
      await scanCommand(targets, {
        profile: opts.profile,
        stealth: opts.stealth,
        save:    opts.save ? "true" : "false",
        noAi:    opts.noAi ? "true" : "false",
        ...(opts.tools ? { tools: opts.tools } : {}),
      });
    });
  return cmd;
}
