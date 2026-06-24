import { NextRequest, NextResponse } from 'next/server';
import { verifyOtp }                 from '../../../../lib/auth-store';
import { addUser, getUser }          from '../../../../lib/permissions-store';

// POST /api/auth/verify  { email, otp }  →  { token, email, role }
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null) as { email?: string; otp?: string } | null;
  const email = body?.email?.trim().toLowerCase();
  const otp   = body?.otp?.trim();

  if (!email || !otp) {
    return NextResponse.json({ error: 'email and otp are required' }, { status: 400 });
  }

  const result = verifyOtp(email, otp);

  if (!result.ok) {
    const messages: Record<string, string> = {
      expired:           'Code expired. Run adversa login to get a new one.',
      invalid:           'Incorrect code.',
      too_many_attempts: 'Too many attempts. Run adversa login to get a new code.',
    };
    return NextResponse.json({ error: messages[(result as { reason: string }).reason] ?? 'Invalid code' }, { status: 401 });
  }

  // Auto-register first-time user (first user becomes admin)
  if (!getUser(email)) {
    addUser(email, 'operator', [], 'system');
  }

  const user = getUser(email)!;
  return NextResponse.json({ token: result.token, email, role: user.role });
}
