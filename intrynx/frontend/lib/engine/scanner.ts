import type { ScanOptions, ScanCallbacks, ScanSummary, LiveFinding, Severity, DiscoveredHost } from './types';
import {
  runNaabu, runNmap, runNuclei, runTestssl,
  runHostDiscovery, runSubfinder, runHttpx, runWhatweb, runFfuf, runSshAudit,
  runSmbEnum, runNetbiosEnum, runSnmpEnum, runLdapEnum, runRpcEnum, runNfsEnum, runRdpFingerprint, runDbEnum,
} from './tool-runners';
import { parseTargets }                             from '../target-parser';
import { generateFindingId }                        from '../finding-id';
import { modulesForPorts }                          from './scan-modules';

function bySeverityCount(findings: LiveFinding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

export async function runScan(opts: ScanOptions, cb: ScanCallbacks): Promise<void> {
  const scanId    = opts.scanId ?? `SCAN-${Date.now()}`;
  const startTime = new Date().toISOString();
  const allFindings: LiveFinding[] = [];
  const tools      = opts.tools;
  const has = (t: ScanOptions['tools'][number]): boolean => tools.includes(t);

  try {
    let targets = parseTargets(opts.targets);
    let hosts: DiscoveredHost[] = [];
    let urls: string[] = [];

    // Pre-seed hosts from previous scan / manual input
    const reusedRaw = process.env.ADVERSA_REUSED_HOSTS;
    if (reusedRaw) {
      try {
        const parsed = JSON.parse(reusedRaw) as DiscoveredHost[];
        if (Array.isArray(parsed)) {
          hosts = parsed;
          for (const h of hosts) cb.onHostDiscovered(h);
        }
      } catch { /* malformed */ }
    }

    // ── Stage: subfinder (subdomain enum) ────────────────────────
    if (has('subfinder')) {
      cb.onStageStart('subfinder');
      cb.onProgress(2, 'Subdomain enumeration…');
      let subs: string[] = [];
      try {
        subs = await runSubfinder(targets, cb);
      } catch (e) {
        cb.onError('subfinder', e instanceof Error ? e.message : String(e));
      }
      // Expand targets with discovered subdomains so downstream stages see them
      const set = new Set([...targets, ...subs]);
      targets = [...set];
      await cb.onStageComplete('subfinder', `${subs.length} subdomain(s) discovered`);
    }

    // ── Stage: host-discovery (ping sweep) ──────────────────────
    if (has('host-discovery')) {
      cb.onStageStart('host-discovery');
      cb.onProgress(8, 'Host discovery…');
      try {
        const live = await runHostDiscovery(targets, cb);
        const byIp = new Map(hosts.map((h) => [h.ip, h]));
        for (const h of live) if (!byIp.has(h.ip)) byIp.set(h.ip, h);
        hosts = [...byIp.values()];
      } catch (e) {
        cb.onError('host-discovery', e instanceof Error ? e.message : String(e));
      }
      await cb.onStageComplete('host-discovery', `${hosts.length} live host(s)`);
    }

    // ── Stage: naabu (port discovery) ────────────────────────────
    if (has('naabu')) {
      cb.onStageStart('naabu');
      cb.onProgress(15, 'Port discovery…');
      try {
        const found = await runNaabu(targets, opts.stealth, cb);
        const byIp = new Map(hosts.map((h) => [h.ip, h]));
        for (const h of found) byIp.set(h.ip, h);
        hosts = [...byIp.values()];
      } catch (e) {
        cb.onError('naabu', e instanceof Error ? e.message : String(e));
      }
      await cb.onStageComplete('naabu', `${hosts.length} host(s) with open ports`);
    }

    // ── Stage: nmap (service fingerprinting) ─────────────────────
    if (has('nmap')) {
      cb.onStageStart('nmap');
      cb.onProgress(30, 'Service fingerprinting…');
      try {
        await runNmap(hosts, opts.stealth, cb);
      } catch (e) {
        cb.onError('nmap', e instanceof Error ? e.message : String(e));
      }
      await cb.onStageComplete('nmap', `${hosts.length} host(s) fingerprinted`);
    }

    // ── Per-service enumeration ──────────────────────────────────
    // The big shift for internal network VAPT: AFTER we know what's open,
    // we run service-specific enum (SMB, NetBIOS, SNMP, LDAP, RPC, NFS,
    // RDP, DBs). Each module is gated by the presence of its trigger ports.
    const openPorts = new Set(hosts.flatMap((h) => h.ports));

    const enumMap: Array<[ScanOptions['tools'][number], (h: DiscoveredHost[], cb: ScanCallbacks) => Promise<LiveFinding[]>]> = [
      ['smb-enum',        runSmbEnum],
      ['netbios-enum',    runNetbiosEnum],
      ['snmp-enum',       runSnmpEnum],
      ['ldap-enum',       runLdapEnum],
      ['rpc-enum',        runRpcEnum],
      ['nfs-enum',        runNfsEnum],
      ['rdp-fingerprint', runRdpFingerprint],
      ['db-enum',         runDbEnum],
    ];

    const enumPromises: Promise<unknown>[] = [];
    for (const [moduleId, runner] of enumMap) {
      if (!has(moduleId)) continue;
      // Check whether any discovered host has a port this module triggers on
      const triggers = modulesForPorts(openPorts);
      if (!triggers.includes(moduleId)) continue;   // no relevant ports — skip silently
      enumPromises.push((async () => {
        cb.onStageStart(moduleId);
        try {
          const f = await runner(hosts, cb);
          allFindings.push(...f);
          await cb.onStageComplete(moduleId, `${f.length} finding(s)`);
        } catch (e) {
          cb.onError(moduleId, e instanceof Error ? e.message : String(e));
          await cb.onStageComplete(moduleId, 'failed');
        }
      })());
    }
    if (enumPromises.length > 0) {
      cb.onProgress(45, `Service enumeration (${enumPromises.length} modules)…`);
      await Promise.all(enumPromises);
    }

    // ── Stage: httpx (HTTP probe) — only if web ports were discovered ────
    const webPorts = new Set([80, 443, 8080, 8443, 8000, 8081, 3000, 5000, 9090, 9000, 7070, 8888, 8181, 8090]);
    const hasWebPorts = hosts.some((h) => h.ports.some((p) => webPorts.has(p)));

    if (has('httpx') && hasWebPorts) {
      cb.onStageStart('httpx');
      cb.onProgress(58, 'HTTP probing…');
      try {
        const out = await runHttpx(hosts, cb);
        urls = out.urls;
        allFindings.push(...out.findings);
      } catch (e) {
        cb.onError('httpx', e instanceof Error ? e.message : String(e));
      }
      await cb.onStageComplete('httpx', `${urls.length} live web service(s)`);
    }

    // ── Web enum (whatweb + ffuf) — gated by web ports being discovered ─
    const webEnumPromises: Promise<unknown>[] = [];
    if (has('whatweb') && urls.length > 0) {
      webEnumPromises.push((async () => {
        cb.onStageStart('whatweb');
        try {
          const f = await runWhatweb(urls, cb);
          allFindings.push(...f);
          await cb.onStageComplete('whatweb', `${f.length} tech fingerprint(s)`);
        } catch (e) {
          cb.onError('whatweb', e instanceof Error ? e.message : String(e));
          await cb.onStageComplete('whatweb', 'failed');
        }
      })());
    }
    if (has('ffuf') && urls.length > 0) {
      webEnumPromises.push((async () => {
        cb.onStageStart('ffuf');
        try {
          const f = await runFfuf(urls, cb, opts.options?.ffufWordlist);
          allFindings.push(...f);
          await cb.onStageComplete('ffuf', `${f.length} path(s) found`);
        } catch (e) {
          cb.onError('ffuf', e instanceof Error ? e.message : String(e));
          await cb.onStageComplete('ffuf', 'failed');
        }
      })());
    }
    if (webEnumPromises.length > 0) {
      cb.onProgress(55, 'Web enumeration…');
      await Promise.all(webEnumPromises);
    }

    // ── Vulnerability + crypto stages in parallel ───────────────
    const vulnPromises: Promise<unknown>[] = [];
    if (has('nuclei')) {
      vulnPromises.push((async () => {
        cb.onStageStart('nuclei');
        try {
          const f = await runNuclei(hosts, cb);
          allFindings.push(...f);
          await cb.onStageComplete('nuclei', `${f.length} match(es)`);
        } catch (e) {
          cb.onError('nuclei', e instanceof Error ? e.message : String(e));
          await cb.onStageComplete('nuclei', 'failed');
        }
      })());
    }
    if (has('testssl')) {
      vulnPromises.push((async () => {
        cb.onStageStart('testssl');
        try {
          const f = await runTestssl(hosts, cb);
          allFindings.push(...f);
          await cb.onStageComplete('testssl', `${f.length} TLS issue(s)`);
        } catch (e) {
          cb.onError('testssl', e instanceof Error ? e.message : String(e));
          await cb.onStageComplete('testssl', 'failed');
        }
      })());
    }
    const hasSshPort = hosts.some((h) => h.ports.includes(22) || h.ports.includes(2222));
    if (has('ssh-audit') && hasSshPort) {
      vulnPromises.push((async () => {
        cb.onStageStart('ssh-audit');
        try {
          const f = await runSshAudit(hosts, cb);
          allFindings.push(...f);
          await cb.onStageComplete('ssh-audit', `${f.length} SSH issue(s)`);
        } catch (e) {
          cb.onError('ssh-audit', e instanceof Error ? e.message : String(e));
          await cb.onStageComplete('ssh-audit', 'failed');
        }
      })());
    }
    if (vulnPromises.length > 0) {
      cb.onProgress(70, 'Vulnerability + crypto scans…');
      await Promise.all(vulnPromises);
    }

    cb.onProgress(85, 'Scanning complete');

    // ── AI triage (optional) ─────────────────────────────────────
    if (process.env.ANTHROPIC_API_KEY) {
      try {
        const load = new Function('p', 'return import(p)') as (p: string) => Promise<{ triageFindings: (f: LiveFinding[]) => Promise<LiveFinding[]> }>;
        const m = await load('../ai-engine');
        const triaged = await m.triageFindings(allFindings);
        allFindings.length = 0;
        allFindings.push(...triaged);
        cb.onProgress(92, 'AI triage complete');
      } catch { /* skip silently */ }
    }

    // ── Persist findings ─────────────────────────────────────────
    let savedCount = 0;
    if (opts.save) {
      try {
        const { saveFindings } = await import('../findings-store');
        savedCount = saveFindings(allFindings, opts.engagementId ?? scanId);
      } catch { /* skip silently */ }
    }

    cb.onProgress(100, 'Done');

    // ── 0-result diagnostic ─────────────────────────────────────
    // If the scan produced nothing, emit an INFO finding explaining likely
    // causes so the operator isn't left guessing. This is silent when the
    // scan found things — only fires on the empty-result failure mode.
    if (hosts.length === 0 && allFindings.length === 0) {
      const diagnostic: LiveFinding = {
        id:        generateFindingId('INFO'),
        title:     'Scan completed with 0 hosts found',
        severity:  'INFO',
        host:      opts.targets.join(','),
        source:    'manual',
        evidence:  [{
          label:   'diagnostic',
          content: [
            'Possible causes (in rough order of likelihood):',
            '',
            '1. TARGET UNREACHABLE — wrong subnet, VPN not connected, or the target',
            '   is on a network this machine cannot route to.',
            `   Try: ping ${opts.targets[0]?.split('/')[0]}`,
            '',
            '2. FIREWALL BLOCKING — macOS firewall or target host firewall is',
            '   dropping the probe packets. Try a higher stealth (slower rate)',
            '   or scan a single known-listening port first.',
            '',
            '3. NO LIVE HOSTS — the CIDR/range you scanned has no responding',
            '   devices. Verify by running `arp -a` (macOS/Linux) to see what your',
            '   machine has talked to recently.',
            '',
            '4. HOST DISCOVERY FAILED — if you used a single IP and only',
            '   host-discovery ran, the host may not respond to ICMP. Try',
            '   disabling host-discovery and running port-scan directly.',
            '',
            '5. SCANNER TOOLS NOT INSTALLED — if nmap/naabu are missing or in',
            '   native-fallback mode, scans of large subnets may time out.',
            '   Run `./run.sh doctor` to verify.',
            '',
            `Targets attempted: ${opts.targets.join(', ')}`,
            `Tools enabled: ${tools.join(', ')}`,
          ].join('\n'),
          timestamp: new Date().toISOString(),
        }],
        status:    'OPEN',
        timestamp: new Date().toISOString(),
      };
      allFindings.push(diagnostic);
      cb.onFinding(diagnostic);
    }

    const endTime = new Date().toISOString();
    const summary: ScanSummary = {
      scanId,
      startTime,
      endTime,
      duration:      new Date(endTime).getTime() - new Date(startTime).getTime(),
      hostsScanned:  hosts.length,
      portsFound:    hosts.reduce((s, h) => s + h.ports.length, 0),
      totalFindings: allFindings.length,
      bySeverity:    bySeverityCount(allFindings),
      savedCount,
      engagementId:  opts.engagementId,
    };
    await cb.onComplete(summary);

  } catch (e) {
    cb.onError('pipeline', e instanceof Error ? e.message : String(e));
  }
}

export { generateFindingId };
