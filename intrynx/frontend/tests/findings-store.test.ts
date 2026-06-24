import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import os   from 'node:os';
import fs   from 'node:fs';
import path from 'node:path';

// Use a unique temp file for each test run so tests are isolated
const TMP_DIR  = path.join(os.tmpdir(), `adversa-test-${Date.now()}`);
const TMP_FILE = path.join(TMP_DIR, 'findings.json');

// Override DATA_PATH before importing the store
process.env.DATA_PATH = TMP_FILE;

import {
  saveFindings,
  getAllFindings,
  getFindingById,
  updateFindingStatus,
  getFindingStats,
  setDataPath,
} from '../lib/findings-store';
import { resetCounters } from '../lib/finding-id';
import type { LiveFinding } from '../lib/engine/types';

function makeFinding(overrides: Partial<LiveFinding> = {}): LiveFinding {
  return {
    id:        'VAPT-CRIT-001',
    title:     'Test Finding',
    severity:  'HIGH',
    host:      '10.0.0.1',
    source:    'nmap',
    evidence:  [{ label: 'test', content: 'raw output', timestamp: new Date().toISOString() }],
    status:    'OPEN',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

beforeEach(() => {
  // Reset temp file and counters before each test
  fs.mkdirSync(TMP_DIR, { recursive: true });
  if (fs.existsSync(TMP_FILE)) fs.unlinkSync(TMP_FILE);
  setDataPath(TMP_FILE);
  resetCounters();
});

describe('findings-store deduplication', () => {

  test('same host + same CVE → only 1 saved, evidence merged', () => {
    const f1 = makeFinding({ id: 'F1', cveIds: ['CVE-2021-44228'], evidence: [{ label: 'ev1', content: 'first',  timestamp: new Date().toISOString() }] });
    const f2 = makeFinding({ id: 'F2', cveIds: ['CVE-2021-44228'], evidence: [{ label: 'ev2', content: 'second', timestamp: new Date().toISOString() }] });

    const added1 = saveFindings([f1]);
    const added2 = saveFindings([f2]);

    assert.equal(added1, 1, 'first finding should be added');
    assert.equal(added2, 0, 'duplicate CVE+host should not be added');

    const all = getAllFindings();
    assert.equal(all.length, 1);
    assert.equal(all[0].evidence.length, 2, 'evidence should be merged');
  });

  test('same host + different CVEs → 2 saved', () => {
    const f1 = makeFinding({ id: 'F1', cveIds: ['CVE-2021-44228'] });
    const f2 = makeFinding({ id: 'F2', cveIds: ['CVE-2022-12345'], title: 'Other Finding' });

    saveFindings([f1]);
    saveFindings([f2]);

    assert.equal(getAllFindings().length, 2);
  });

  test('same host + same title but no CVE → deduped as 1', () => {
    const f1 = makeFinding({ id: 'F1', title: 'Open SSH Port', cveIds: [] });
    const f2 = makeFinding({ id: 'F2', title: 'Open SSH Port', cveIds: [] });

    saveFindings([f1]);
    saveFindings([f2]);

    assert.equal(getAllFindings().length, 1);
  });

  test('SLA deadline for CRITICAL is within 25 hours from now', () => {
    const f = makeFinding({ id: 'F1', severity: 'CRITICAL', cveIds: [] });
    saveFindings([f]);

    const saved = getAllFindings()[0];
    assert.ok(saved.slaDeadline, 'slaDeadline should be set for CRITICAL');
    const deadline = new Date(saved.slaDeadline!).getTime();
    const now      = Date.now();
    assert.ok(deadline > now,          'deadline should be in the future');
    assert.ok(deadline < now + 25 * 3_600_000, 'deadline should be within 25 hours');
  });

  test('SLA deadline for INFO is undefined', () => {
    const f = makeFinding({ id: 'F1', severity: 'INFO', cveIds: [] });
    saveFindings([f]);
    const saved = getAllFindings()[0];
    assert.equal(saved.slaDeadline, undefined);
  });

  test('getFindingStats returns correct bySeverity counts', () => {
    saveFindings([
      makeFinding({ id: 'F1', severity: 'CRITICAL', title: 'C1' }),
      makeFinding({ id: 'F2', severity: 'HIGH',     title: 'H1', host: '10.0.0.2' }),
      makeFinding({ id: 'F3', severity: 'HIGH',     title: 'H2', host: '10.0.0.3' }),
      makeFinding({ id: 'F4', severity: 'MEDIUM',   title: 'M1', host: '10.0.0.4' }),
    ]);

    const stats = getFindingStats();
    assert.equal(stats.total, 4);
    assert.equal(stats.bySeverity.CRITICAL, 1);
    assert.equal(stats.bySeverity.HIGH, 2);
    assert.equal(stats.bySeverity.MEDIUM, 1);
    assert.equal(stats.bySeverity.LOW, 0);
  });

  test('updateFindingStatus changes status correctly', () => {
    saveFindings([makeFinding({ id: 'F-UPDT', title: 'Status Test', cveIds: [] })]);
    const result = updateFindingStatus('F-UPDT', 'VERIFIED');
    assert.equal(result, true);
    const saved = getFindingById('F-UPDT');
    assert.ok(saved);
    assert.equal(saved.status, 'VERIFIED');
  });

  test('updateFindingStatus returns false for unknown id', () => {
    assert.equal(updateFindingStatus('NO-SUCH-ID', 'CLOSED'), false);
  });

  test('getAllFindings returns [] when file does not exist', () => {
    if (fs.existsSync(TMP_FILE)) fs.unlinkSync(TMP_FILE);
    assert.deepEqual(getAllFindings(), []);
  });

});
