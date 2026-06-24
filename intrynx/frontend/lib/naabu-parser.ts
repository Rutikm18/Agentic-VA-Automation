import type { DiscoveredHost } from './engine/types';

export type NaabuResult = {
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
};

interface NaabuRaw {
  ip?: string;
  host?: string;
  port?: number | string;
  protocol?: string;
}

export function parseNaabuLine(jsonl: string): NaabuResult | null {
  if (!jsonl || !jsonl.trim()) return null;
  try {
    const raw = JSON.parse(jsonl.trim()) as NaabuRaw;
    const ip   = raw.ip ?? raw.host;
    const port = Number(raw.port);
    if (!ip || !port || isNaN(port)) return null;
    const protocol = (raw.protocol === 'udp' ? 'udp' : 'tcp') as 'tcp' | 'udp';
    return { ip, port, protocol };
  } catch {
    return null;
  }
}

export function groupNaabuResults(results: NaabuResult[]): DiscoveredHost[] {
  const hostMap = new Map<string, { ports: number[]; services: { port: number; proto: string }[] }>();

  for (const r of results) {
    if (!hostMap.has(r.ip)) {
      hostMap.set(r.ip, { ports: [], services: [] });
    }
    const entry = hostMap.get(r.ip)!;
    if (!entry.ports.includes(r.port)) {
      entry.ports.push(r.port);
      entry.services.push({ port: r.port, proto: r.protocol });
    }
  }

  return Array.from(hostMap.entries()).map(([ip, data]) => ({
    ip,
    ports:    data.ports.sort((a, b) => a - b),
    services: data.services,
  }));
}
