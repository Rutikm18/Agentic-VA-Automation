import type { FindingSeverity } from "./findings-store";

export interface OpenVASFinding {
  title: string;
  severity: FindingSeverity;
  cvss: string;
  cves: string[];
  affectedHost: string;
  port: string;
  description: string;
  solution?: string;
  insight?: string;
  detection?: string;
  nvtOid?: string;
  qod?: string;
}

export interface OpenVASTaskState {
  taskId: string;
  status: "queued" | "running" | "done" | "error";
  progress: number;
  findings: OpenVASFinding[];
  error?: string;
}

const taskStore = new Map<string, OpenVASTaskState>();

export function getTask(taskId: string): OpenVASTaskState | undefined {
  return taskStore.get(taskId);
}

export function setTask(taskId: string, state: OpenVASTaskState): void {
  taskStore.set(taskId, state);
}

export function cvssToSeverity(score: number): FindingSeverity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0)    return "LOW";
  return "INFO";
}

export async function startOpenVASScan(params: {
  targets: string[];
  gvmHost: string;
  gvmPort: number;
  gvmUser: string;
  gvmPassword: string;
  scanConfig: string;
}): Promise<{ taskId: string }> {
  const taskId = `openvas-${Date.now()}`;
  setTask(taskId, { taskId, status: "queued", progress: 0, findings: [] });

  // Run the actual GVM scan asynchronously in the background
  runOpenVASScanBackground(taskId, params);

  return { taskId };
}

async function runOpenVASScanBackground(taskId: string, params: {
  targets: string[];
  gvmHost: string;
  gvmPort: number;
  gvmUser: string;
  gvmPassword: string;
  scanConfig: string;
}): Promise<void> {
  setTask(taskId, { taskId, status: "running", progress: 5, findings: [] });

  try {
    // python-gvm must be available in the agent; here we shell out to a helper script
    const { spawn } = await import("child_process");
    const { default: os }   = await import("os");
    const { default: path } = await import("path");
    const { default: fs }   = await import("fs");

    const scriptPath = path.join(os.tmpdir(), `adversa-openvas-${taskId}.py`);
    const outputPath = path.join(os.tmpdir(), `adversa-openvas-out-${taskId}.json`);

    const pyScript = `
import json, time
from gvm.connections import TLSConnection
from gvm.protocols import Gmp
from gvm.transforms import EtreeTransform

GVM_HOST     = ${JSON.stringify(params.gvmHost)}
GVM_PORT     = ${params.gvmPort}
GVM_USER     = ${JSON.stringify(params.gvmUser)}
GVM_PASSWORD = ${JSON.stringify(params.gvmPassword)}
TARGETS      = ${JSON.stringify(params.targets.join(","))}
TASK_ID      = ${JSON.stringify(taskId)}
OUT_PATH     = ${JSON.stringify(outputPath)}
SCAN_CONFIG_NAME = ${JSON.stringify(params.scanConfig)}

CONFIG_IDS = {
    "full-fast":          "daba56c8-73ec-11df-a475-002264764cea",
    "full-fast-ultimate": "698f691e-7489-11df-9d8c-002264764cea",
    "empty":              "085569ce-73ed-11df-83c3-002264764cea",
    "system-discovery":   "8715c877-47a0-438d-98a3-27c7a6ab2196",
}
FULL_PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

with TLSConnection(hostname=GVM_HOST, port=GVM_PORT) as conn:
    with Gmp(conn, transform=EtreeTransform()) as gmp:
        gmp.authenticate(GVM_USER, GVM_PASSWORD)

        target_resp = gmp.create_target(
            name=f"adversa-{TASK_ID}",
            hosts=TARGETS,
            port_list_id=FULL_PORT_LIST_ID,
        )
        target_id = target_resp.get("id")

        task_resp = gmp.create_task(
            name=f"adversa-task-{TASK_ID}",
            config_id=CONFIG_IDS.get(SCAN_CONFIG_NAME, CONFIG_IDS["full-fast"]),
            target_id=target_id,
            scanner_id=OPENVAS_SCANNER_ID,
        )
        gvm_task_id = task_resp.get("id")

        gmp.start_task(gvm_task_id)

        while True:
            time.sleep(30)
            report = gmp.get_task(gvm_task_id)
            status = report.find("task/status").text
            progress = int(report.find("task/progress").text or 0)
            if status in ("Done", "Stopped"):
                break

        report_id = report.find("task/last_report/report").get("id")
        results = gmp.get_results(task_id=gvm_task_id, filter_string="levels=hmlg rows=-1")

        findings = []
        for result in results.findall(".//result"):
            severity = float(result.findtext("severity") or "0")
            if severity < 0.1:
                continue
            nvt = result.find("nvt")
            cves = [ref.get("id") for ref in nvt.findall("refs/ref[@type='cve']")]
            sev_map = {s: l for s, l in [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")]}
            sev_label = next((l for s, l in sev_map.items() if severity >= s), "INFO")
            findings.append({
                "title":        result.findtext("name"),
                "severity":     sev_label,
                "cvss":         str(severity),
                "cves":         cves,
                "affectedHost": result.findtext("host/hostname") or result.findtext("host"),
                "port":         result.findtext("port"),
                "description":  result.findtext("description"),
                "solution":     nvt.findtext("solution"),
                "insight":      nvt.findtext("insight"),
                "detection":    nvt.findtext("detection"),
                "nvtOid":       nvt.get("oid"),
                "qod":          result.findtext("qod/value"),
            })

        gmp.delete_task(gvm_task_id, ultimate=True)
        gmp.delete_target(target_id, ultimate=True)

        with open(OUT_PATH, "w") as f:
            json.dump({"findings": findings, "count": len(findings)}, f)
`;

    fs.writeFileSync(scriptPath, pyScript);

    await new Promise<void>((resolve) => {
      const proc = spawn("python3", [scriptPath], { timeout: 7_200_000 });
      proc.on("error", () => resolve());
      proc.on("close", () => resolve());
    });

    fs.unlink(scriptPath, () => {});

    let findings: OpenVASFinding[] = [];
    if (fs.existsSync(outputPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(outputPath, "utf-8")) as { findings: OpenVASFinding[] };
        findings = data.findings;
        fs.unlinkSync(outputPath);
      } catch { /* ignore */ }
    }

    setTask(taskId, { taskId, status: "done", progress: 100, findings });
  } catch (err) {
    setTask(taskId, { taskId, status: "error", progress: 0, findings: [], error: String(err) });
  }
}
