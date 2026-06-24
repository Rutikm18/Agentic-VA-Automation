import { NextRequest, NextResponse } from "next/server";
import { readCases, createCase } from "../../../lib/cases-store";

export async function GET() {
  const cases = readCases();
  return NextResponse.json(cases);
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const newCase = createCase(body);
    return NextResponse.json(newCase, { status: 201 });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 400 });
  }
}
