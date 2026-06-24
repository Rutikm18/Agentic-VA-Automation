import { NextRequest, NextResponse } from 'next/server';
import { verifyToken }               from './auth-store';
import { isEmailAllowed }            from './permissions-store';

export interface AuthContext {
  email: string;
}

type Handler<P = Record<string, string>> = (
  req:     NextRequest,
  ctx:     AuthContext,
  params?: P,
) => Promise<NextResponse> | NextResponse;

export function withAuth<P = Record<string, string>>(
  handler: Handler<P>,
): (req: NextRequest, extra?: { params?: Promise<P> }) => Promise<NextResponse> {
  return async (req, extra) => {
    const authHeader = req.headers.get('authorization') ?? '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      return NextResponse.json(
        { error: 'Not authenticated. Run: adversa login' },
        { status: 401 },
      );
    }

    const payload = verifyToken(token);
    if (!payload) {
      return NextResponse.json(
        { error: 'Session expired. Run: adversa login' },
        { status: 401 },
      );
    }

    if (!isEmailAllowed(payload.email)) {
      return NextResponse.json(
        { error: `${payload.email} is not authorized. Ask an admin to add you.` },
        { status: 403 },
      );
    }

    const params = extra?.params ? await extra.params : undefined;
    return handler(req, { email: payload.email }, params as P);
  };
}
