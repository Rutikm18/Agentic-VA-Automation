import { NextResponse } from "next/server";
import { graphStore } from "../../../../../lib/graph-store";

// GET /engagements/{id}/attack-graph → D3-compatible graph JSON
export async function GET() {
  return NextResponse.json(graphStore.getD3Graph());
}
