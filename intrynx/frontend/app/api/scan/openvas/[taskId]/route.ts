import { NextRequest, NextResponse } from "next/server";
import { getTask } from "../../../../../lib/openvas-client";
import { createFinding } from "../../../../../lib/findings-store";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ taskId: string }> },
) {
  const { taskId } = await params;
  const task = getTask(taskId);

  if (!task) {
    return NextResponse.json({ error: "Task not found." }, { status: 404 });
  }

  return NextResponse.json({
    taskId: task.taskId,
    status: task.status,
    progress: task.progress,
    findings: task.findings,
    findingCount: task.findings.length,
    error: task.error,
    stats: {
      critical: task.findings.filter((f) => f.severity === "CRITICAL").length,
      high:     task.findings.filter((f) => f.severity === "HIGH").length,
      medium:   task.findings.filter((f) => f.severity === "MEDIUM").length,
      low:      task.findings.filter((f) => f.severity === "LOW").length,
    },
  });
}
