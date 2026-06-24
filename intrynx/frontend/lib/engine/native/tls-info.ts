/**
 * Native TLS / SSL inspection — no testssl.sh required for the basics.
 *
 * Uses Node's built-in tls module to:
 *   - retrieve the server certificate (subject, issuer, SAN, expiry)
 *   - detect the negotiated protocol version + cipher
 *   - flag obvious issues: self-signed, expired, expiring-soon, weak signature
 *
 * For deep TLS auditing (BEAST/POODLE/forward-secrecy/etc.) the operator can
 * still install testssl.sh and the external runner will be used instead.
 */
import { connect as tlsConnect } from 'tls';

export interface TlsInfoResult {
  host:           string;
  port:           number;
  protocol?:      string;
  cipher?:        { name: string; standardName?: string; version?: string };
  certificate?: {
    subject?:    string;
    issuer?:     string;
    validFrom?:  string;
    validTo?:    string;
    daysToExpiry?: number;
    altNames?:   string[];
    fingerprint?: string;
    selfSigned?: boolean;
    signatureAlgorithm?: string;
  };
  issues:         string[];
  durationMs:     number;
  error?:         string;
}

const WEAK_SIGNATURES = ['md2WithRSAEncryption', 'md5WithRSAEncryption', 'sha1WithRSAEncryption'];
const WEAK_PROTOCOLS  = ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'];

export function nativeTlsInfo(host: string, port: number): Promise<TlsInfoResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    const issues: string[] = [];
    const sock = tlsConnect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: 5000,
    });

    sock.once('secureConnect', () => {
      const cert = sock.getPeerCertificate(true);
      const cipher = sock.getCipher();
      const protocol = sock.getProtocol() ?? undefined;

      const expiry = cert.valid_to ? new Date(cert.valid_to).getTime() : 0;
      const daysToExpiry = expiry ? Math.floor((expiry - Date.now()) / 86400000) : undefined;

      // Issue detection
      if (protocol && WEAK_PROTOCOLS.includes(protocol)) issues.push(`Weak protocol: ${protocol}`);
      if (daysToExpiry !== undefined && daysToExpiry < 0)  issues.push(`Certificate expired ${Math.abs(daysToExpiry)} days ago`);
      else if (daysToExpiry !== undefined && daysToExpiry < 30) issues.push(`Certificate expires in ${daysToExpiry} days`);
      if (cert.issuer?.CN === cert.subject?.CN) issues.push('Self-signed certificate');
      const sigAlg = (cert as unknown as { signatureAlgorithm?: string }).signatureAlgorithm;
      if (sigAlg && WEAK_SIGNATURES.includes(sigAlg)) issues.push(`Weak signature algorithm: ${sigAlg}`);

      const cn = (s: unknown): string | undefined => {
        if (typeof s === 'string') return s;
        if (Array.isArray(s)) return s[0];
        return undefined;
      };
      resolve({
        host, port,
        protocol,
        cipher: cipher ? { name: cipher.name, standardName: cipher.standardName, version: cipher.version } : undefined,
        certificate: {
          subject:    cn(cert.subject?.CN),
          issuer:     cn(cert.issuer?.CN),
          validFrom:  cert.valid_from,
          validTo:    cert.valid_to,
          daysToExpiry,
          altNames:   typeof cert.subjectaltname === 'string' ? cert.subjectaltname.split(', ').map((s) => s.replace(/^DNS:/, '')) : undefined,
          fingerprint: cert.fingerprint256,
          selfSigned: cn(cert.issuer?.CN) === cn(cert.subject?.CN),
          signatureAlgorithm: sigAlg,
        },
        issues,
        durationMs: Date.now() - start,
      });
      sock.end();
    });

    sock.on('timeout', () => { sock.destroy(); resolve({ host, port, issues, durationMs: Date.now() - start, error: 'timeout' }); });
    sock.on('error',   (err) => resolve({ host, port, issues, durationMs: Date.now() - start, error: err.message }));
  });
}
