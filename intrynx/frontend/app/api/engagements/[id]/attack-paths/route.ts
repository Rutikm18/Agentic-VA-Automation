import { NextResponse } from "next/server";
import { graphStore } from "../../../../../lib/graph-store";

// GET /engagements/{id}/attack-paths?page=1&pageSize=10
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const page     = Math.max(1, parseInt(searchParams.get("page")     ?? "1",  10));
  const pageSize = Math.max(1, parseInt(searchParams.get("pageSize") ?? "10", 10));
  return NextResponse.json(graphStore.listPaths(page, pageSize));
}
