import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parseNmapXml }                           from '../lib/nmap-parser';
import { parseNucleiLine, nucleiSeverityToSeverity } from '../lib/nuclei-parser';
import { parseTestsslJson }                        from '../lib/testssl-parser';
import { parseNaabuLine, groupNaabuResults }       from '../lib/naabu-parser';
import { resetCounters }                           from '../lib/finding-id';

// ── nmap sample XML ──────────────────────────────────────────────
const NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="host1.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
        <script id="http-title" output="Login Page"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <hostnames></hostnames>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0.35"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.3" addrtype="ipv4"/>
  </host>
</nmaprun>`;

// ── nuclei sample JSONL ──────────────────────────────────────────
const NUCLEI_VALID = JSON.stringify({
  'template-id': 'CVE-2021-44228',
  info: {
    name: 'Log4j RCE',
    severity: 'critical',
    description: 'Apache Log4j2 RCE',
    classification: { 'cve-id': ['CVE-2021-44228'] },
  },
  host: 'http://10.0.0.1:8080',
  ip: '10.0.0.1',
  port: '8080',
  'matched-at': 'http://10.0.0.1:8080/api/login',
  'extracted-results': ['jndi://...'],
  timestamp: '2024-01-01T00:00:00Z',
});

// ── testssl sample JSON ──────────────────────────────────────────
const TESTSSL_VALID = JSON.stringify([
  { id: 'SSLv3', severity: 'CRITICAL', finding: 'offered (NOT ok)', cve: 'CVE-2014-3566' },
  { id: 'TLS1',  severity: 'WARN',     finding: 'offered with 256 cipher suites' },
  { id: 'cert',  severity: 'OK',       finding: 'Certificate valid' },
  { id: 'debug', severity: 'DEBUG',    finding: 'Debug info only' },
]);

// ── naabu sample JSONL ───────────────────────────────────────────
const NAABU_LINE = JSON.stringify({ ip: '10.0.0.1', port: 80, protocol: 'tcp' });

// ════════════════════════════════════════════════════════════════

describe('nmap-parser', () => {
  test('parses 2 up-hosts from XML', () => {
    const hosts = parseNmapXml(NMAP_XML);
    assert.equal(hosts.length, 2);
  });

  test('first host has correct IP and hostnames', () => {
    const hosts = parseNmapXml(NMAP_XML);
    assert.equal(hosts[0].ip, '10.0.0.1');
    assert.ok(hosts[0].hostnames.includes('host1.local'));
  });

  test('first host has 3 services (open + filtered)', () => {
    const hosts = parseNmapXml(NMAP_XML);
    assert.equal(hosts[0].services.length, 3);
    const open = hosts[0].services.filter((s) => s.state === 'open');
    assert.equal(open.length, 2);
  });

  test('NSE script result extracted for port 80', () => {
    const hosts = parseNmapXml(NMAP_XML);
    const httpTitle = hosts[0].scripts.find((s) => s.id === 'http-title');
    assert.ok(httpTitle);
    assert.equal(httpTitle.output, 'Login Page');
  });

  test('skips down hosts', () => {
    const hosts = parseNmapXml(NMAP_XML);
    assert.ok(hosts.every((h) => h.status === 'up'));
    assert.ok(!hosts.some((h) => h.ip === '10.0.0.3'));
  });

  test('returns [] for empty string', () => {
    assert.deepEqual(parseNmapXml(''), []);
  });

  test('returns [] for malformed XML', () => {
    assert.deepEqual(parseNmapXml('<not xml>'), []);
  });
});

// ════════════════════════════════════════════════════════════════

describe('nuclei-parser', () => {
  test('parses valid JSONL line with CVE', () => {
    const match = parseNucleiLine(NUCLEI_VALID);
    assert.ok(match);
    assert.equal(match.templateId, 'CVE-2021-44228');
    assert.equal(match.name, 'Log4j RCE');
    assert.equal(match.severity, 'critical');
    assert.ok(match.cveIds.includes('CVE-2021-44228'));
    assert.equal(match.port, 8080);
    assert.equal(match.extractedResults.length, 1);
  });

  test('returns null for empty string', () => {
    assert.equal(parseNucleiLine(''), null);
  });

  test('returns null for malformed JSON', () => {
    assert.equal(parseNucleiLine('{not json}'), null);
  });

  test('returns null for JSON missing template-id', () => {
    assert.equal(parseNucleiLine(JSON.stringify({ host: 'http://x.com' })), null);
  });

  test('nucleiSeverityToSeverity maps critical → CRITICAL', () => {
    assert.equal(nucleiSeverityToSeverity('critical'), 'CRITICAL');
  });

  test('nucleiSeverityToSeverity maps unknown → INFO', () => {
    assert.equal(nucleiSeverityToSeverity('unknown'), 'INFO');
  });
});

// ════════════════════════════════════════════════════════════════

describe('testssl-parser', () => {
  test('skips OK severity entries', () => {
    resetCounters();
    const findings = parseTestsslJson(TESTSSL_VALID, '10.0.0.1', 443);
    assert.ok(!findings.some((f) => f.title.startsWith('cert:')));
  });

  test('skips DEBUG severity entries', () => {
    resetCounters();
    const findings = parseTestsslJson(TESTSSL_VALID, '10.0.0.1', 443);
    assert.ok(!findings.some((f) => f.title.startsWith('debug:')));
  });

  test('maps WARN → HIGH', () => {
    resetCounters();
    const findings = parseTestsslJson(TESTSSL_VALID, '10.0.0.1', 443);
    const tls1 = findings.find((f) => f.title.startsWith('TLS1:'));
    assert.ok(tls1);
    assert.equal(tls1.severity, 'HIGH');
  });

  test('maps CRITICAL correctly', () => {
    resetCounters();
    const findings = parseTestsslJson(TESTSSL_VALID, '10.0.0.1', 443);
    const sslv3 = findings.find((f) => f.title.startsWith('SSLv3:'));
    assert.ok(sslv3);
    assert.equal(sslv3.severity, 'CRITICAL');
  });

  test('returns [] for invalid JSON', () => {
    assert.deepEqual(parseTestsslJson('{bad json}', '10.0.0.1', 443), []);
  });

  test('returns [] for empty string', () => {
    assert.deepEqual(parseTestsslJson('', '10.0.0.1', 443), []);
  });
});

// ════════════════════════════════════════════════════════════════

describe('naabu-parser', () => {
  test('parses valid naabu JSONL line', () => {
    const result = parseNaabuLine(NAABU_LINE);
    assert.ok(result);
    assert.equal(result.ip, '10.0.0.1');
    assert.equal(result.port, 80);
    assert.equal(result.protocol, 'tcp');
  });

  test('returns null for empty string', () => {
    assert.equal(parseNaabuLine(''), null);
  });

  test('returns null for invalid JSON', () => {
    assert.equal(parseNaabuLine('{bad}'), null);
  });

  test('returns null for JSON missing ip and port', () => {
    assert.equal(parseNaabuLine(JSON.stringify({ protocol: 'tcp' })), null);
  });

  test('groupNaabuResults groups two results for same IP', () => {
    const results = [
      { ip: '10.0.0.5', port: 80,  protocol: 'tcp' as const },
      { ip: '10.0.0.5', port: 443, protocol: 'tcp' as const },
      { ip: '10.0.0.6', port: 22,  protocol: 'tcp' as const },
    ];
    const hosts = groupNaabuResults(results);
    assert.equal(hosts.length, 2);
    const h = hosts.find((x) => x.ip === '10.0.0.5');
    assert.ok(h);
    assert.deepEqual(h.ports, [80, 443]);
    assert.equal(h.services.length, 2);
  });
});
