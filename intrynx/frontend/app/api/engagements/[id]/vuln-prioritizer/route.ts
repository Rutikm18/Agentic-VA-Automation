import { NextResponse } from "next/server";
import { vulnPrioritizer, type FindingInput, type AssetInput } from "../../../../../lib/ai-engine";

// Demo findings dataset for the prioritizer
const DEMO_FINDINGS: FindingInput[] = [
  { id: "VAPT-CRIT-001", title: "Unconstrained Delegation — DC01",           severity: "CRITICAL", cvss: 9.0, affectedHost: "10.0.0.10", exploitValidated: true,  mitreTechnique: "T1134.001", description: "DC01 trusted for unconstrained delegation" },
  { id: "VAPT-CRIT-002", title: "Kerberoastable Service Account",             severity: "CRITICAL", cvss: 8.8, affectedHost: "10.0.1.20", exploitValidated: true,  mitreTechnique: "T1558.003", description: "svc_backup uses RC4-HMAC encryption" },
  { id: "VAPT-CRIT-003", title: "Log4Shell (CVE-2021-44228)",                 severity: "CRITICAL", cvss: 10.0, cveId: "CVE-2021-44228", affectedHost: "192.168.10.10", exploitValidated: true,  mitreTechnique: "T1190" },
  { id: "VAPT-HIGH-001", title: "SMB Signing Not Required — 4 hosts",         severity: "HIGH",     cvss: 8.1, affectedHost: "10.0.1.10", exploitValidated: true,  mitreTechnique: "T1557.001" },
  { id: "VAPT-HIGH-002", title: "DCOM Remote Execution — No Alerting",        severity: "HIGH",     cvss: 7.5, affectedHost: "10.0.1.11", exploitValidated: false, mitreTechnique: "T1021.003" },
  { id: "VAPT-HIGH-003", title: "AD CS ESC1 — UserAuthentication Template",   severity: "HIGH",     cvss: 8.0, affectedHost: "10.0.0.15", exploitValidated: false, mitreTechnique: "T1649" },
  { id: "VAPT-MED-001",  title: "Anonymous LDAP Bind Enabled",                severity: "MEDIUM",   cvss: 5.3, affectedHost: "10.0.0.10", exploitValidated: false, mitreTechnique: "T1087.002" },
  { id: "VAPT-MED-002",  title: "Password Min Length 8 — Below Recommendation",severity: "MEDIUM",  cvss: 4.0, affectedHost: "corp.local", exploitValidated: false, mitreTechnique: "T1110" },
];

const DEMO_ASSETS: Record<string, AssetInput> = {
  "10.0.0.10":       { id: "dc01",    label: "DC01",      criticality: "CRITICAL", internetExposed: false, zone: "MGMT", lateralReachableCount: 317, daysSinceLastPatch: 45  },
  "10.0.1.20":       { id: "svc-sql", label: "SVC-SQL",   criticality: "CRITICAL", internetExposed: false, zone: "CORP", lateralReachableCount: 12,  daysSinceLastPatch: 180 },
  "192.168.10.10":   { id: "web-01",  label: "WEB-01",    criticality: "HIGH",     internetExposed: true,  zone: "DMZ",  lateralReachableCount: 8,   daysSinceLastPatch: 30  },
  "10.0.1.10":       { id: "ws-042",  label: "WS-042",    criticality: "MEDIUM",   internetExposed: false, zone: "CORP", lateralReachableCount: 10,  daysSinceLastPatch: 90  },
  "10.0.1.11":       { id: "ws-128",  label: "WS-128",    criticality: "MEDIUM",   internetExposed: false, zone: "CORP", lateralReachableCount: 8,   daysSinceLastPatch: 120 },
  "10.0.0.15":       { id: "ca01",    label: "corp-CA",   criticality: "CRITICAL", internetExposed: false, zone: "MGMT", lateralReachableCount: 15,  daysSinceLastPatch: 200 },
  "corp.local":      { id: "domain",  label: "corp.local",criticality: "HIGH",     internetExposed: false, zone: "CORP", lateralReachableCount: 842, daysSinceLastPatch: 0   },
};

// GET /engagements/{id}/vuln-prioritizer
export async function GET() {
  const scored = DEMO_FINDINGS.map((f) => {
    const asset = DEMO_ASSETS[f.affectedHost] ?? {
      id: "unknown", label: f.affectedHost, criticality: "MEDIUM" as const,
      internetExposed: false, zone: "CORP", lateralReachableCount: 5, daysSinceLastPatch: 90,
    };
    const score    = vulnPrioritizer.predictPriority(f, asset);
    const shap     = vulnPrioritizer.explainPrediction(f, asset);
    return { finding: f, asset, score, shap };
  }).sort((a, b) => b.score - a.score);

  return NextResponse.json({ findings: scored, total: scored.length });
}
