import { NextRequest, NextResponse } from "next/server";
import { addComment } from "../../../../../lib/cases-store";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    const { author, content } = await req.json();
    if (!content?.trim()) return NextResponse.json({ error: "Content required" }, { status: 400 });
    const updated = addComment(id, author ?? "Anonymous", content.trim());
    if (!updated) return NextResponse.json({ error: "Case not found" }, { status: 404 });
    return NextResponse.json(updated);
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 400 });
  }
}
