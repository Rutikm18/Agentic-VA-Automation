import { NextRequest, NextResponse } from 'next/server';
import { withAuth }                  from '../../../../lib/auth-middleware';
import { getAllUsers, addUser, isAdmin } from '../../../../lib/permissions-store';
import type { UserRole }             from '../../../../lib/permissions-store';

// GET /api/admin/users  →  list all users
export const GET = withAuth((req: NextRequest, ctx) => {
  if (!isAdmin(ctx.email)) {
    return NextResponse.json({ error: 'Admin only' }, { status: 403 });
  }
  return NextResponse.json(getAllUsers());
});

// POST /api/admin/users  { email, role, allowedScopes }  →  add user
export const POST = withAuth(async (req: NextRequest, ctx) => {
  if (!isAdmin(ctx.email)) {
    return NextResponse.json({ error: 'Admin only' }, { status: 403 });
  }

  const body = await req.json().catch(() => null) as {
    email?: string;
    role?: UserRole;
    allowedScopes?: string[];
  } | null;

  if (!body?.email?.includes('@')) {
    return NextResponse.json({ error: 'Valid email required' }, { status: 400 });
  }

  const user = addUser(
    body.email,
    body.role ?? 'operator',
    body.allowedScopes ?? [],
    ctx.email,
  );

  return NextResponse.json(user, { status: 201 });
});
