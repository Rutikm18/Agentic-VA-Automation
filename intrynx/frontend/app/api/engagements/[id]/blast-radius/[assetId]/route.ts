import { NextResponse } from "next/server";
import { graphStore } from "../../../../../../lib/graph-store";

// GET /engagements/{id}/blast-radius/{assetId}
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string; assetId: string }> }
) {
  const { assetId } = await params;
  const result = graphStore.getBlastRadius(assetId);
  return NextResponse.json(result);
}
