import { NextRequest, NextResponse }                 from 'next/server';
import { verifyToken }                                from '../../../../../lib/auth-store';
import { removeUser, updateScopes, getUser, isAdmin } from '../../../../../lib/permissions-store';

function getCallerEmail(req: NextRequest): string | null {
  const auth = req.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  return verifyToken(token)?.email ?? null;
}

// PUT /api/admin/users/[email]  { allowedScopes }  →  update scopes
export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ email: string }> },
) {
  const caller = getCallerEmail(req);
  if (!caller) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  if (!isAdmin(caller)) return NextResponse.json({ error: 'Admin only' }, { status: 403 });

  const { email: rawEmail } = await params;
  const target = decodeURIComponent(rawEmail ?? '');
  const body   = await req.json().catch(() => null) as { allowedScopes?: string[] } | null;

  const ok = updateScopes(target, body?.allowedScopes ?? []);
  if (!ok) return NextResponse.json({ error: 'User not found' }, { status: 404 });

  return NextResponse.json(getUser(target));
}

// DELETE /api/admin/users/[email]  →  remove user
export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ email: string }> },
) {
  const caller = getCallerEmail(req);
  if (!caller) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  if (!isAdmin(caller)) return NextResponse.json({ error: 'Admin only' }, { status: 403 });

  const { email: rawEmail } = await params;
  const target = decodeURIComponent(rawEmail ?? '');

  if (target === caller) {
    return NextResponse.json({ error: 'Cannot remove yourself' }, { status: 400 });
  }

  const ok = removeUser(target);
  if (!ok) return NextResponse.json({ error: 'User not found' }, { status: 404 });

  return NextResponse.json({ ok: true });
}
