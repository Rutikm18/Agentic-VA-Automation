/**
 * Typed error envelope.
 *
 * Every external interaction (spawn, fetch, fs, LLM) wraps its failure in an
 * AdversaError. Each error carries a user-facing title, an explanation, a
 * suggested remediation, and a structured code for automation / telemetry.
 *
 * Design rules:
 *   1. No naked string errors past this layer.
 *   2. Every error is actionable — `fix` is mandatory.
 *   3. The default render is human-friendly; JSON output is available for tooling.
 */

export type ErrorCode =
  // Tool / binary errors
  | 'TOOL_MISSING'
  | 'TOOL_SPAWN_FAILED'
  | 'TOOL_EXIT_NONZERO'
  | 'TOOL_TIMEOUT'
  | 'TOOL_PERMISSION_DENIED'
  | 'TOOL_LIBPCAP_MISSING'
  // Network / server errors
  | 'SERVER_UNREACHABLE'
  | 'SERVER_TIMEOUT'
  | 'SERVER_AUTH_REQUIRED'
  | 'SERVER_FORBIDDEN'
  | 'SERVER_NOT_FOUND'
  | 'SERVER_INTERNAL'
  // LLM errors
  | 'LLM_KEY_MISSING'
  | 'LLM_QUOTA_EXCEEDED'
  | 'LLM_UNREACHABLE'
  | 'LLM_PARSE_FAILED'
  // Auth errors
  | 'AUTH_NO_SESSION'
  | 'AUTH_SESSION_EXPIRED'
  | 'AUTH_OUT_OF_SCOPE'
  // Filesystem errors
  | 'FS_PERMISSION_DENIED'
  | 'FS_NOT_FOUND'
  | 'FS_DISK_FULL'
  // Config errors
  | 'CONFIG_MISSING'
  | 'CONFIG_INVALID'
  // Generic
  | 'UNKNOWN';

export interface AdversaErrorOpts {
  code:     ErrorCode;
  title:    string;             // one-line summary, e.g. "naabu not found"
  detail?:  string;             // 1–3 sentences explaining what happened
  fix:      string;             // concrete next step the user can take
  context?: Record<string, unknown>;
  cause?:   unknown;
}

export class AdversaError extends Error {
  readonly code:    ErrorCode;
  readonly title:   string;
  readonly detail?: string;
  readonly fix:     string;
  readonly context: Record<string, unknown>;
  readonly cause:   unknown;

  constructor(opts: AdversaErrorOpts) {
    super(opts.title);
    this.name    = 'AdversaError';
    this.code    = opts.code;
    this.title   = opts.title;
    this.detail  = opts.detail;
    this.fix     = opts.fix;
    this.context = opts.context ?? {};
    this.cause   = opts.cause;
  }

  toJSON(): object {
    return {
      code:    this.code,
      title:   this.title,
      detail:  this.detail,
      fix:     this.fix,
      context: this.context,
    };
  }

  /**
   * Render for terminal display. Multi-line, ANSI colors.
   *
   * @param opts.useColor  - colorize (default: TTY detect)
   * @param opts.withMark  - prepend ✗ symbol (default: true). Set false when the
   *                         caller already prints its own status marker.
   * @param opts.verbose   - include Context: line for debugging
   */
  render(opts: { useColor?: boolean; withMark?: boolean; verbose?: boolean } = {}): string {
    const useColor = opts.useColor ?? !!process.stdout.isTTY;
    const withMark = opts.withMark ?? true;
    const verbose  = opts.verbose  ?? false;

    const c = useColor
      ? { red: '\x1b[1;31m', cyan: '\x1b[1;36m', dim: '\x1b[2m', reset: '\x1b[0m', bold: '\x1b[1m' }
      : { red: '', cyan: '', dim: '', reset: '', bold: '' };

    const lines: string[] = [];
    const mark = withMark ? `${c.red}✗ ${c.reset}` : '';
    lines.push(`${mark}${c.bold}${this.title}${c.reset}`);

    if (this.detail) {
      // Show only the first non-empty line of detail in the default render —
      // tool stderr can be hundreds of lines and drowns out the fix.
      const firstDetail = this.detail.split('\n').map((l) => l.trim()).find((l) => l.length > 0);
      if (firstDetail) lines.push(`  ${c.dim}${firstDetail.slice(0, 200)}${c.reset}`);
    }
    lines.push(`  ${c.cyan}Fix:${c.reset} ${this.fix}`);

    if (verbose && Object.keys(this.context).length > 0) {
      lines.push(`  ${c.dim}Context: ${JSON.stringify(this.context)}${c.reset}`);
    }
    return lines.join('\n');
  }
}

// ── Builders for common error classes ────────────────────────────────

export const Errors = {
  toolMissing(tool: string, installHint: string): AdversaError {
    return new AdversaError({
      code:   'TOOL_MISSING',
      title:  `${tool} is not installed or not on PATH`,
      detail: `The ${tool} binary could not be found. The scan stage that depends on it will be skipped.`,
      fix:    installHint,
      context:{ tool },
    });
  },

  toolSpawnFailed(tool: string, errMsg: string): AdversaError {
    return new AdversaError({
      code:   'TOOL_SPAWN_FAILED',
      title:  `${tool} failed to start`,
      detail: errMsg,
      fix:    `Run \`adversa doctor\` to diagnose. Most often this is a missing library (e.g. libpcap for naabu) — try \`brew install libpcap\` then re-run.`,
      context:{ tool },
    });
  },

  toolExitNonzero(tool: string, code: number, stderr?: string): AdversaError {
    return new AdversaError({
      code:   'TOOL_EXIT_NONZERO',
      title:  `${tool} exited with code ${code}`,
      detail: stderr ? stderr.slice(0, 500) : undefined,
      fix:    `Run \`adversa doctor\` to check for common issues. For permission problems on Linux/macOS, some tools need raw socket access (sudo) for SYN scans — try lowering stealth or using TCP-connect mode.`,
      context:{ tool, code },
    });
  },

  toolLibpcapMissing(tool: string): AdversaError {
    return new AdversaError({
      code:   'TOOL_LIBPCAP_MISSING',
      title:  `${tool} cannot find libpcap`,
      detail: `On macOS this is the Homebrew libpcap not being on the dynamic linker path.`,
      fix:    `Run: \`brew install libpcap\` then \`sudo DYLD_LIBRARY_PATH=/opt/homebrew/lib ${tool} -version\` once to prime the linker.`,
      context:{ tool },
    });
  },

  serverUnreachable(url: string, cause?: unknown): AdversaError {
    return new AdversaError({
      code:   'SERVER_UNREACHABLE',
      title:  `Cannot reach ADVERSA API server at ${url}`,
      detail: `The server may not be running, or a firewall is blocking the connection.`,
      fix:    `Start the server with \`./run.sh start\`, or set ADVERSA_SERVER env var to the correct URL.`,
      context:{ url },
      cause,
    });
  },

  authNoSession(): AdversaError {
    return new AdversaError({
      code:   'AUTH_NO_SESSION',
      title:  `Not logged in`,
      fix:    `Run \`./run.sh app\` and log in, or \`./run.sh cli login\` for the command-line login.`,
    });
  },

  authSessionExpired(): AdversaError {
    return new AdversaError({
      code:   'AUTH_SESSION_EXPIRED',
      title:  `Session expired`,
      detail: `JWT sessions last 7 days.`,
      fix:    `Run \`./run.sh cli login\` (or use the wizard) to refresh your session.`,
    });
  },

  authOutOfScope(target: string): AdversaError {
    return new AdversaError({
      code:   'AUTH_OUT_OF_SCOPE',
      title:  `Target ${target} is outside your authorized scopes`,
      detail: `Operators are restricted to the CIDRs an admin has assigned them.`,
      fix:    `Ask an admin to widen your scope: \`./run.sh cli admin set-scope <your-email> --scope "<cidr>"\`.`,
      context:{ target },
    });
  },

  llmKeyMissing(): AdversaError {
    return new AdversaError({
      code:   'LLM_KEY_MISSING',
      title:  `ANTHROPIC_API_KEY is not set`,
      detail: `AI commentary, attack-path analysis, AI Q&A, and AI reports require an Anthropic API key.`,
      fix:    `Add ANTHROPIC_API_KEY=sk-ant-... to .env.local and restart the server with \`./run.sh stop && ./run.sh start\`.`,
    });
  },

  llmUnreachable(cause?: unknown): AdversaError {
    return new AdversaError({
      code:   'LLM_UNREACHABLE',
      title:  `Could not reach the Anthropic API`,
      detail: `Network failure, invalid key, or quota exceeded.`,
      fix:    `Check your network connection, verify ANTHROPIC_API_KEY is valid, and check your account quota at console.anthropic.com.`,
      cause,
    });
  },

  configMissing(name: string): AdversaError {
    return new AdversaError({
      code:   'CONFIG_MISSING',
      title:  `Required configuration missing: ${name}`,
      fix:    `Run \`./run.sh setup\` to generate a default .env.local, then edit ${name} to a valid value.`,
      context:{ name },
    });
  },

  // ── Wrap an unknown error into an AdversaError ──────────────────
  wrap(e: unknown, fallbackFix: string): AdversaError {
    if (e instanceof AdversaError) return e;
    return new AdversaError({
      code:   'UNKNOWN',
      title:  e instanceof Error ? e.message : String(e),
      fix:    fallbackFix,
      cause:  e,
    });
  },
};

/** Detect the shape of common spawn/library failures and translate to AdversaError. */
export function diagnoseSpawnError(tool: string, code: number, stderr: string): AdversaError {
  // nuclei exits 2 when it cannot find any templates to run — distinct from a real error
  if (tool === 'nuclei' && code === 2) {
    return new AdversaError({
      code:   'TOOL_EXIT_NONZERO',
      title:  'nuclei: no templates found',
      detail: 'nuclei exited with code 2 — it could not find any templates in its search paths.',
      fix:    'Run `nuclei -update-templates` to download the official template set, or set NUCLEI_TEMPLATE_DIR=/path/to/nuclei-templates.',
      context:{ tool, code },
    });
  }

  if (code === -1 || /ENOENT/.test(stderr) || /not found/i.test(stderr)) {
    const hints: Record<string, string> = {
      naabu:   'Install: `brew install libpcap go && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` then add ~/go/bin to PATH.',
      nuclei:  'Install: `brew install go && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` then add ~/go/bin to PATH.',
      nmap:    'Install: `brew install nmap`.',
      testssl: 'Install: `git clone https://github.com/drwetter/testssl.sh ~/testssl.sh && sudo ln -s ~/testssl.sh/testssl.sh /usr/local/bin/testssl.sh`.',
    };
    return Errors.toolMissing(tool, hints[tool] ?? `Install ${tool} and ensure it's on PATH.`);
  }
  if (/libpcap|dyld.*pcap/i.test(stderr)) return Errors.toolLibpcapMissing(tool);

  // Config-dir creation failure — most common when the tool was invoked with a
  // non-writable HOME or XDG_CONFIG_HOME. Distinct from real OS permission denied.
  if (/mkdir.*permission denied|failed to create.*directory|failed to write config/i.test(stderr)) {
    return new AdversaError({
      code:   'TOOL_PERMISSION_DENIED',
      title:  `${tool} could not write its config directory`,
      detail: stderr.slice(0, 300),
      fix:    `Set ${tool === 'nuclei' ? 'NUCLEI_CONFIG_DIR' : 'a tool-specific config env var'} to a writable directory (e.g. \`export NUCLEI_CONFIG_DIR=$HOME/.config/nuclei\`) and restart the server.`,
      context:{ tool },
    });
  }

  if (/permission denied|operation not permitted/i.test(stderr)) {
    return new AdversaError({
      code:   'TOOL_PERMISSION_DENIED',
      title:  `${tool} blocked by OS permissions`,
      detail: stderr.slice(0, 300),
      fix:    `Some scanners need elevated privileges for raw sockets. Try a higher stealth level (slower, less invasive) or run from a sudo-able terminal.`,
      context:{ tool },
    });
  }

  // Rate-limited / connection failures — usually means the target wasn't reachable
  if (/connection refused|no route to host|timeout/i.test(stderr)) {
    return new AdversaError({
      code:   'TOOL_EXIT_NONZERO',
      title:  `${tool} could not reach the target`,
      detail: stderr.slice(0, 300),
      fix:    `Verify the target is reachable: try \`ping <ip>\` from the same machine. For internal networks, ensure you're on the right VPN/segment.`,
      context:{ tool },
    });
  }

  return Errors.toolExitNonzero(tool, code, stderr);
}
