import { NextRequest, NextResponse } from 'next/server';
import { Resend }                    from 'resend';
import { generateOtp }               from '../../../../lib/auth-store';
import { isEmailAllowed }            from '../../../../lib/permissions-store';

// POST /api/auth/request  { email }  →  sends OTP via Resend
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null) as { email?: string } | null;
  const email = body?.email?.trim().toLowerCase();

  if (!email || !email.includes('@')) {
    return NextResponse.json({ error: 'Valid email required' }, { status: 400 });
  }

  if (!isEmailAllowed(email)) {
    // Return same message as success to avoid email enumeration
    return NextResponse.json({ ok: true, message: 'If that email is allowed, a code is on its way.' });
  }

  const otp     = generateOtp(email);
  const apiKey  = process.env.RESEND_API_KEY;

  if (!apiKey) {
    // Dev mode — print OTP to server console
    console.log(`\n[ADVERSA DEV] OTP for ${email}: ${otp}\n`);
    return NextResponse.json({ ok: true, dev: true, otp });
  }

  const from = process.env.RESEND_FROM ?? 'Adversa <noreply@adversa.security>';
  const resend = new Resend(apiKey);

  const { error } = await resend.emails.send({
    from,
    to:      email,
    subject: 'Your ADVERSA login code',
    html: `
      <div style="font-family:monospace;background:#050A0E;color:#C8E8F0;padding:32px;border-radius:8px">
        <h2 style="color:#00D4FF;margin:0 0 16px">ADVERSA</h2>
        <p style="margin:0 0 8px">Your one-time login code:</p>
        <p style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#00FF88;margin:16px 0">${otp}</p>
        <p style="color:#3D7A94;font-size:12px;margin:16px 0 0">Expires in 10 minutes. Do not share this code.</p>
      </div>
    `,
  });

  if (error) {
    console.error('Resend error:', error);
    return NextResponse.json({ error: 'Failed to send email' }, { status: 500 });
  }

  return NextResponse.json({ ok: true, message: 'Code sent. Check your email.' });
}
