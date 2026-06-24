import { NextResponse } from "next/server";
import { detectionStore, type SIEMConfig } from "../../../../../../lib/detection-store";

// GET /engagements/{id}/detection-validation/siem-config
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return NextResponse.json({ configs: detectionStore.getSiemConfigs(id) });
}

// POST /engagements/{id}/detection-validation/siem-config
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await request.json();
  const { type, host, port, token, index, workspace } = body;

  if (!type || !host || !token) {
    return NextResponse.json({ error: "type, host, and token are required" }, { status: 400 });
  }

  const config = detectionStore.saveSiemConfig(id, {
    type, host, port, token, index, workspace, configured: false,
  } as SIEMConfig);

  return NextResponse.json({ config }, { status: 201 });
}
