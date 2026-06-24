import { NextResponse } from "next/server";
import { graphStore } from "../../../../../lib/graph-store";

// GET /engagements/{id}/chokepoints
export async function GET() {
  const chokepoints = graphStore.getChokepoints();
  return NextResponse.json({ chokepoints, total: chokepoints.length });
}
