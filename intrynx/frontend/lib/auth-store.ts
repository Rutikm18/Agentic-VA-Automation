import crypto from 'crypto';
import jwt    from 'jsonwebtoken';

const JWT_SECRET  = process.env.AUTH_SECRET ?? 'adversa-dev-secret-change-me';
const JWT_EXPIRES = '7d';
const OTP_TTL_MS  = 10 * 60 * 1000; // 10 minutes

interface OtpEntry {
  otp:       string;
  expiresAt: number;
  attempts:  number;
}

// In-memory OTP store (process-scoped — fine for single-instance dev/prod)
const otpStore = new Map<string, OtpEntry>();

export interface SessionPayload {
  email: string;
  iat?:  number;
  exp?:  number;
}

// ── OTP generation ────────────────────────────────────────────────
export function generateOtp(email: string): string {
  const otp = String(crypto.randomInt(100_000, 999_999));
  otpStore.set(email.toLowerCase(), {
    otp,
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts:  0,
  });
  return otp;
}

export type OtpVerifyResult =
  | { ok: true;  token: string }
  | { ok: false; reason: 'expired' | 'invalid' | 'too_many_attempts' };

export function verifyOtp(email: string, otp: string): OtpVerifyResult {
  const key   = email.toLowerCase();
  const entry = otpStore.get(key);

  if (!entry || Date.now() > entry.expiresAt) {
    otpStore.delete(key);
    return { ok: false, reason: 'expired' };
  }

  entry.attempts++;

  if (entry.attempts > 5) {
    otpStore.delete(key);
    return { ok: false, reason: 'too_many_attempts' };
  }

  if (entry.otp !== otp.trim()) {
    return { ok: false, reason: 'invalid' };
  }

  otpStore.delete(key);
  const token = jwt.sign({ email: key }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  return { ok: true, token };
}

// ── JWT verification ─────────────────────────────────────────────
export function verifyToken(token: string): SessionPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET) as SessionPayload;
  } catch {
    return null;
  }
}
