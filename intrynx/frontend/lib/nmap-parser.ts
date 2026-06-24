import { XMLParser } from 'fast-xml-parser';

export type NmapService = {
  port: number;
  proto: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  name?: string;
  product?: string;
  version?: string;
  extrainfo?: string;
};

export type NmapScriptResult = {
  id: string;
  output: string;
};

export type NmapHost = {
  ip: string;
  hostnames: string[];
  os?: string;
  status: 'up' | 'down';
  services: NmapService[];
  scripts: NmapScriptResult[];
};

const parser = new XMLParser({
  ignoreAttributes:    false,
  attributeNamePrefix: '@_',
  isArray: (tagName) =>
    ['host', 'port', 'hostname', 'osmatch', 'script'].includes(tagName),
});

function toArray<T>(val: T | T[] | undefined): T[] {
  if (val === undefined) return [];
  return Array.isArray(val) ? val : [val];
}

function extractScripts(container: Record<string, unknown> | undefined): NmapScriptResult[] {
  if (!container) return [];
  const scripts = toArray(container['script'] as unknown);
  return scripts
    .filter((s): s is Record<string, string> => s != null && typeof s === 'object')
    .map((s) => ({ id: String(s['@_id'] ?? ''), output: String(s['@_output'] ?? '') }))
    .filter((s) => s.id);
}

export function parseNmapXml(xml: string): NmapHost[] {
  if (!xml || !xml.trim()) return [];

  let parsed: Record<string, unknown>;
  try {
    parsed = parser.parse(xml) as Record<string, unknown>;
  } catch {
    return [];
  }

  const nmaprun = parsed['nmaprun'] as Record<string, unknown> | undefined;
  if (!nmaprun) return [];

  const rawHosts = toArray(nmaprun['host'] as unknown);
  const results: NmapHost[] = [];

  for (const rawHost of rawHosts) {
    const h = rawHost as Record<string, unknown>;

    const statusArr = toArray(h['status'] as unknown);
    const state = (statusArr[0] as Record<string, string> | undefined)?.['@_state'] ?? 'down';
    if (state !== 'up') continue;

    // IP address
    const addresses = toArray(h['address'] as unknown) as Record<string, string>[];
    const ipEntry   = addresses.find((a) => a['@_addrtype'] === 'ipv4');
    const ip        = ipEntry?.['@_addr'] ?? '';
    if (!ip) continue;

    // Hostnames
    const hostnamesContainer = h['hostnames'] as Record<string, unknown> | undefined;
    const hostnames: string[] = toArray(hostnamesContainer?.['hostname'] as unknown)
      .filter((n): n is Record<string, string> => n != null && typeof n === 'object')
      .filter((n) => ['PTR', 'A'].includes(n['@_type'] ?? ''))
      .map((n) => n['@_name'])
      .filter(Boolean);

    // OS
    const osArr = toArray(h['os'] as unknown) as Record<string, unknown>[];
    const osMatches = osArr.flatMap((o) => toArray(o['osmatch'] as unknown)) as Record<string, string>[];
    const os = osMatches[0]?.['@_name'];

    // Ports
    const portsContainer = h['ports'] as Record<string, unknown> | undefined;
    const rawPorts       = toArray(portsContainer?.['port'] as unknown) as Record<string, unknown>[];

    const services: NmapService[] = [];
    const portScripts: NmapScriptResult[] = [];

    for (const rp of rawPorts) {
      const portId = Number(rp['@_portid'] ?? 0);
      const proto  = (rp['@_protocol'] ?? 'tcp') as 'tcp' | 'udp';

      const stateObj = (rp['state'] as Record<string, string> | undefined);
      const portState = (stateObj?.['@_state'] ?? 'closed') as 'open' | 'closed' | 'filtered';

      const svc = rp['service'] as Record<string, string> | undefined;

      services.push({
        port:      portId,
        proto,
        state:     portState,
        name:      svc?.['@_name'],
        product:   svc?.['@_product'],
        version:   svc?.['@_version'],
        extrainfo: svc?.['@_extrainfo'],
      });

      portScripts.push(...extractScripts(rp as Record<string, unknown>));
    }

    // Host-level scripts
    const hostScripts = extractScripts(h['hostscript'] as Record<string, unknown> | undefined);

    results.push({
      ip,
      hostnames,
      os,
      status: 'up',
      services,
      scripts: [...portScripts, ...hostScripts],
    });
  }

  return results;
}
