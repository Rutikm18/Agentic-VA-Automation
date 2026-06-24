import { NextResponse } from "next/server";

export interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  tactic: string[];
  url: string;
  mitigations: string[];
}

/* In-memory cache — 1 hour TTL */
let cache: { data: MitreTechnique[]; ts: number } | null = null;
const CACHE_TTL = 3_600_000;

const MITRE_STIX_URL =
  "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

function parseTactics(obj: Record<string, unknown>): string[] {
  const killChain = obj.kill_chain_phases as { kill_chain_name: string; phase_name: string }[] | undefined;
  if (!Array.isArray(killChain)) return [];
  return killChain
    .filter((k) => k.kill_chain_name === "mitre-attack")
    .map((k) => k.phase_name.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()));
}

async function fetchMitre(): Promise<MitreTechnique[]> {
  const res = await fetch(MITRE_STIX_URL, { next: { revalidate: 3600 } });
  if (!res.ok) throw new Error(`MITRE fetch failed: ${res.status}`);

  const stix = (await res.json()) as { objects: Record<string, unknown>[] };

  const techniques = stix.objects.filter(
    (o) =>
      o.type === "attack-pattern" &&
      !(o.revoked as boolean) &&
      !(o.x_mitre_deprecated as boolean)
  );

  const mitigationRels = stix.objects.filter(
    (o) => o.type === "relationship" && o.relationship_type === "mitigates"
  ) as { source_ref: string; target_ref: string }[];

  const mitigations = stix.objects.filter((o) => o.type === "course-of-action") as {
    id: string;
    name: string;
  }[];

  const mitigationById = new Map(mitigations.map((m) => [m.id, m.name]));

  return techniques.map((t) => {
    const extRefs = t.external_references as { source_name: string; external_id: string; url: string }[];
    const mitreRef = extRefs?.find((r) => r.source_name === "mitre-attack");
    const techniqueId = mitreRef?.external_id ?? (t.id as string);
    const url = mitreRef?.url ?? `https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}`;

    const relatedMitigations = mitigationRels
      .filter((r) => r.target_ref === (t.id as string))
      .map((r) => mitigationById.get(r.source_ref) ?? "")
      .filter(Boolean);

    return {
      id: techniqueId,
      name: (t.name as string) ?? "",
      description: ((t.description as string) ?? "").slice(0, 400),
      tactic: parseTactics(t),
      url,
      mitigations: relatedMitigations,
    };
  });
}

export async function GET() {
  try {
    if (cache && Date.now() - cache.ts < CACHE_TTL) {
      return NextResponse.json(cache.data);
    }

    const data = await fetchMitre();
    cache = { data, ts: Date.now() };
    return NextResponse.json(data);
  } catch (e) {
    /* Return cached stale data on network failure rather than erroring */
    if (cache) return NextResponse.json(cache.data);
    return NextResponse.json({ error: String(e) }, { status: 503 });
  }
}
