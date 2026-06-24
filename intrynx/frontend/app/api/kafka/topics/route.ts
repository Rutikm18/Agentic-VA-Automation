import { NextResponse } from "next/server";
import { agentsStore } from "../../../../lib/agents-store";

export async function GET() {
  return NextResponse.json({ topics: agentsStore.listTopics() });
}
