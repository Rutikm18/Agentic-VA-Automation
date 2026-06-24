import { NextResponse } from "next/server";

// BloodHoundCollector wrapper — simulates collection status and DA shortest paths.

export async function GET() {
  const result = {
    collectionStatus: "completed",
    collectionMethods: ["All"],
    collectedAt: "2026-05-10T09:45:00Z",
    stats: { users: 842, computers: 317, groups: 94, sessions: 1203, acls: 5412 },

    // BloodHoundCollector.query_da_paths — shortest paths to Domain Admins
    daPaths: [
      {
        id: "PATH-001",
        length: 2,
        riskScore: 9.8,
        nodes: [
          { label: "helpdesk1", type: "User",     critical: false },
          { label: "Domain Admins", type: "Group", critical: true },
        ],
        edges: [
          { source: "helpdesk1", target: "Domain Admins", relation: "GenericWrite", technique: "T1484.001" },
        ],
        narrative: "helpdesk1 has GenericWrite on Domain Admins group → can add self to DA.",
        cypherQuery: "MATCH p=shortestPath((u:User {name:'helpdesk1@corp.local'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p",
      },
      {
        id: "PATH-002",
        length: 3,
        riskScore: 9.1,
        nodes: [
          { label: "svc_backup",   type: "User",     critical: false },
          { label: "Backup Operators", type: "Group", critical: false },
          { label: "DC01",         type: "Computer", critical: true  },
          { label: "Domain Admins",type: "Group",    critical: true  },
        ],
        edges: [
          { source: "svc_backup",       target: "Backup Operators", relation: "MemberOf",  technique: "T1078.002" },
          { source: "Backup Operators",  target: "DC01",             relation: "CanRDP",    technique: "T1021.001" },
          { source: "DC01",             target: "Domain Admins",    relation: "HasSession", technique: "T1558.003" },
        ],
        narrative: "svc_backup (Backup Operators) → RDP to DC01 → DA session harvesting via Kerberoast.",
        cypherQuery: "MATCH p=shortestPath((u:User {name:'svc_backup@corp.local'})-[*1..10]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p",
      },
      {
        id: "PATH-003",
        length: 4,
        riskScore: 8.5,
        nodes: [
          { label: "WS-042",       type: "Computer", critical: false },
          { label: "john.admin",   type: "User",     critical: false },
          { label: "Enterprise Admins", type: "Group", critical: true },
          { label: "Domain Admins",type: "Group",    critical: true  },
        ],
        edges: [
          { source: "WS-042",          target: "john.admin",       relation: "HasSession",   technique: "T1078.002" },
          { source: "john.admin",      target: "Enterprise Admins", relation: "MemberOf",    technique: "" },
          { source: "Enterprise Admins",target: "Domain Admins",   relation: "GenericAll",  technique: "T1484.001" },
        ],
        narrative: "WS-042 (unconstrained delegation) has active session for john.admin (EA) → pivot to DA.",
        cypherQuery: "MATCH p=shortestPath((c:Computer {name:'WS-042.CORP.LOCAL'})-[*1..10]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p",
      },
    ],
  };

  return NextResponse.json(result);
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const { collectionMethods = ["All"] } = body;

  // Simulate async collection job
  return NextResponse.json({
    jobId: Math.random().toString(36).slice(2, 9).toUpperCase(),
    status: "queued",
    collectionMethods,
    estimatedSeconds: 45,
    message: "BloodHound collection job queued. Poll GET /api/ad/bloodhound for results.",
  }, { status: 202 });
}
