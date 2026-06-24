import type { Severity } from './engine/types';

const SEV_PREFIX: Record<Severity, string> = {
  CRITICAL: 'CRIT',
  HIGH:     'HIGH',
  MEDIUM:   'MED',
  LOW:      'LOW',
  INFO:     'INFO',
};

const counters = new Map<string, number>();

export function generateFindingId(severity: Severity): string {
  const prefix = SEV_PREFIX[severity];
  const next = (counters.get(prefix) ?? 0) + 1;
  counters.set(prefix, next);
  return `VAPT-${prefix}-${String(next).padStart(3, '0')}`;
}

export function resetCounters(): void {
  counters.clear();
}
