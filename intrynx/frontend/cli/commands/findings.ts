import { Command }                      from "commander";
import { getAllFindings, getFindingById } from "../../lib/findings-store";
import type { Severity }                 from "../../lib/engine/types";
import * as out                          from "../ui/output";

export function buildFindingsCommand(): Command {
  const cmd = new Command("findings");
  cmd.description("View and manage VAPT findings");

  /* ── list ─────────────────────────────────────────────────── */
  cmd
    .command("list", { isDefault: true })
    .description("List all findings")
    .option("-s, --severity <level>", "Filter: critical | high | medium | low | info")
    .option("-t, --target <host>",    "Filter by affected host (substring match)")
    .option("--status <status>",      "Filter by status (OPEN, IN_REVIEW, …)")
    .option("--json",                 "Output raw JSON")
    .action((opts: {
      severity?: string;
      target?: string;
      status?: string;
      json?: boolean;
    }) => {
      let findings = getAllFindings();

      if (opts.severity) {
        const sev = opts.severity.toUpperCase() as Severity;
        findings = findings.filter((f) => f.severity === sev);
      }
      if (opts.target) {
        const q = opts.target.toLowerCase();
        findings = findings.filter((f) => f.host.toLowerCase().includes(q));
      }
      if (opts.status) {
        const s = opts.status.toUpperCase();
        findings = findings.filter((f) => f.status === s);
      }

      if (opts.json) {
        process.stdout.write(JSON.stringify(findings, null, 2) + "\n");
        return;
      }

      out.banner();
      out.rule();
      out.info(`${findings.length} finding${findings.length !== 1 ? "s" : ""}${opts.severity ? ` · severity: ${opts.severity.toUpperCase()}` : ""}${opts.target ? ` · target: ${opts.target}` : ""}`);
      out.rule();
      process.stdout.write("\n");
      out.findingsTable(findings);
    });

  /* ── show ─────────────────────────────────────────────────── */
  cmd
    .command("show <id>")
    .description("Show full detail for a finding")
    .action((id: string) => {
      const f = getFindingById(id);
      if (!f) {
        out.error(`Finding not found: ${id}`);
        process.exit(1);
      }
      out.findingDetail(f);
    });

  /* ── stats ────────────────────────────────────────────────── */
  cmd
    .command("stats")
    .description("Show severity distribution and SLA summary")
    .action(() => {
      const findings = getAllFindings();
      const bySev: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      const byStatus: Record<string, number> = {};
      let breached = 0;

      for (const f of findings) {
        bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
        byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
        if (f.slaDeadline && Date.now() > new Date(f.slaDeadline).getTime() && f.status === "OPEN") {
          breached++;
        }
      }

      out.banner();
      out.rule();
      out.info(`FINDINGS SUMMARY — ${findings.length} total`);
      out.rule();
      process.stdout.write("\n");

      const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      for (const sev of sevOrder) {
        const count = bySev[sev] ?? 0;
        if (count === 0) continue;
        const bar = "█".repeat(Math.min(count, 40));
        process.stdout.write(`  ${out.sevBadge(sev)}  ${String(count).padStart(3)}  ${bar}\n`);
      }

      process.stdout.write("\n");
      out.info("Status breakdown:");
      for (const [status, count] of Object.entries(byStatus)) {
        process.stdout.write(`  ${status.padEnd(20)} ${count}\n`);
      }

      if (breached > 0) {
        process.stdout.write("\n");
        process.stdout.write(`  \x1b[1;31m⚠  ${breached} OPEN finding${breached !== 1 ? "s" : ""} past SLA deadline\x1b[0m\n`);
      }

      process.stdout.write("\n");
    });

  return cmd;
}
