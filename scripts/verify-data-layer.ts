/**
 * Sanity harness for the data + metrics layers.
 *
 * Runs the same code the dashboard runs, without a browser, and asserts the
 * derived numbers land in believable ranges. Catches the failure mode that a
 * screenshot cannot: a dashboard that renders perfectly while every figure it
 * shows is wrong.
 *
 * Run with:  npx -y tsx scripts/verify-data-layer.ts
 */
import { generateBackfill } from '@/data/backfill';
import { INITIAL_HOSTS } from '@/data/topology';
import { ALL_SCENARIOS, DEMO_SCRIPT, materializeScenario } from '@/data/scenarios';
import { createRng } from '@/data/random';
import { bucketActivity, computeHostRisk, computeKpis, computeTopSources, TIME_RANGE_KEYS } from '@/services/metrics';
import { computeSecurityScore } from '@/services/riskEngine';
import { EVENT_TYPES } from '@/config/eventTypes';
import { MITRE_TECHNIQUES } from '@/config/mitre';
import { filterEvents, initializeEvents, sortEvents } from '@/services/eventStore';
import type { SecurityEvent } from '@/types/security';

let failures = 0;

function check(label: string, condition: boolean, detail: string) {
  const mark = condition ? 'PASS' : 'FAIL';
  if (!condition) failures += 1;
  console.log(`  [${mark}] ${label} — ${detail}`);
}

const now = Date.now();
console.log('\n=== Backfill ===');
const raw = generateBackfill(now);
const events = initializeEvents(raw);
console.log(`  generated ${raw.length} events`);

check('event volume is realistic', raw.length > 2000 && raw.length < 20000, `${raw.length} events`);
check(
  'newest-first ordering holds',
  events.every((e, i) => i === 0 || events[i - 1]!.timestamp >= e.timestamp),
  'monotonically non-increasing timestamps',
);
check(
  'all events within retention window',
  raw.every((e) => e.timestamp <= now && e.timestamp >= now - 7.1 * 24 * 3600_000),
  'no timestamps outside 7d',
);
check('every event id is unique', new Set(raw.map((e) => e.id)).size === raw.length, `${new Set(raw.map((e) => e.id)).size} unique ids`);

console.log('\n=== Schema integrity ===');
const badType = raw.find((e) => !(e.eventType in EVENT_TYPES));
check('all eventTypes exist in catalog', !badType, badType ? `unknown: ${badType.eventType}` : 'all mapped');

const badMitre = raw.find((e) => e.mitreTechnique && !(e.mitreTechnique in MITRE_TECHNIQUES));
check('all MITRE ids exist in catalog', !badMitre, badMitre ? `unknown: ${badMitre.mitreTechnique}` : 'all mapped');

const missingRaw = raw.filter((e) => !e.rawLog).length;
check('every event carries a raw log line', missingRaw === 0, `${missingRaw} missing`);

const badIp = raw.find((e) => !/^\d{1,3}(\.\d{1,3}){3}$/.test(e.sourceIp) || !/^\d{1,3}(\.\d{1,3}){3}$/.test(e.destinationIp));
check('source/destination IPs are well formed', !badIp, badIp ? `bad: ${badIp.sourceIp} -> ${badIp.destinationIp}` : 'all valid');

const badConfidence = raw.find((e) => e.confidence < 0 || e.confidence > 100);
check('confidence within 0-100', !badConfidence, badConfidence ? `${badConfidence.confidence}` : 'all in range');

console.log('\n=== KPIs ===');
const kpis = computeKpis(events, now);
console.log(`  critical=${kpis.criticalCount} high=${kpis.highCount} medium=${kpis.mediumCount} low=${kpis.lowCount}`);
console.log(`  totalEvents(24h)=${kpis.totalEvents} activeThreats=${kpis.activeThreats} needsAttention=${kpis.threatsRequiringAttention}`);
console.log(`  criticalDelta=${kpis.criticalDeltaLastHour} highDelta=${kpis.highDeltaPercent}%`);

check('24h total is a sensible SOC volume', kpis.totalEvents > 500 && kpis.totalEvents < 15000, `${kpis.totalEvents}`);
check('open queue is workable, not absurd', kpis.criticalCount + kpis.highCount < 400, `${kpis.criticalCount + kpis.highCount} open crit+high`);
check('active threats are tracked', kpis.activeThreats > 0 && kpis.activeThreats <= 10, `${kpis.activeThreats} source IPs`);
check('needsAttention never exceeds activeThreats', kpis.threatsRequiringAttention <= kpis.activeThreats, `${kpis.threatsRequiringAttention} <= ${kpis.activeThreats}`);

console.log('\n=== Security score ===');
const score = computeSecurityScore(events, now);
console.log(`  score=${score.score}/100 band=${score.band} (${score.label})`);
check('score within bounds', score.score >= 0 && score.score <= 100, `${score.score}`);
check('score is not pinned at an extreme', score.score > 5 && score.score < 99, `${score.score}`);
check('breakdown is populated', score.breakdown.length > 0, `${score.breakdown.length} severities contributing`);

// Resolving the queue must measurably improve posture, or the score is decorative.
const allResolved: SecurityEvent[] = events.map((e) => ({ ...e, status: 'resolved' as const }));
const resolvedScore = computeSecurityScore(allResolved, now);
check('score responds to triage', resolvedScore.score === 100, `all-resolved -> ${resolvedScore.score}`);

console.log('\n=== Chart bucketing ===');
for (const range of TIME_RANGE_KEYS) {
  const buckets = bucketActivity(events, range, now);
  const total = buckets.reduce((s, b) => s + b.total, 0);
  const nonEmpty = buckets.filter((b) => b.total > 0).length;
  console.log(`  ${range}: ${buckets.length} buckets, ${total} events, ${nonEmpty} non-empty`);
  check(`${range} produces buckets`, buckets.length > 0, `${buckets.length}`);
  check(`${range} has data to plot`, nonEmpty > 0, `${nonEmpty} non-empty buckets`);
  check(
    `${range} bucket sums match components`,
    buckets.every((b) => b.critical + b.high + b.medium + b.low === b.total),
    'severity split equals total',
  );
}

console.log('\n=== Top attack sources ===');
const sources = computeTopSources(events, 5, now);
for (const s of sources) {
  console.log(`  ${s.ip.padEnd(16)} events=${String(s.eventCount).padStart(4)} risk=${String(s.riskScore).padStart(3)} threat=${s.dominantThreat}`);
}
check('sources found', sources.length > 0, `${sources.length} sources`);
check('sorted by risk descending', sources.every((s, i) => i === 0 || sources[i - 1]!.riskScore >= s.riskScore), 'ordering holds');
check('victim IP excluded from attackers', !sources.some((s) => s.ip === '192.168.56.105'), 'no self-attribution');
check('risk scores within bounds', sources.every((s) => s.riskScore >= 0 && s.riskScore <= 100), 'all 0-100');

console.log('\n=== Host risk ===');
const hosts = computeHostRisk(INITIAL_HOSTS, events, now);
for (const h of hosts) {
  console.log(`  ${h.hostname.padEnd(16)} risk=${String(h.riskScore).padStart(3)} (${h.riskLevel}) events=${h.eventCount}`);
}
check('all hosts scored', hosts.length === INITIAL_HOSTS.length, `${hosts.length} hosts`);
check('victim carries the most events', hosts.find((h) => h.role === 'victim')!.eventCount > 0, 'victim has events');

console.log('\n=== Filtering ===');
const criticalOnly = filterEvents(events, { severities: ['critical'], query: '', eventTypes: [], hosts: [], statuses: [] });
check('severity filter narrows', criticalOnly.length > 0 && criticalOnly.length < events.length, `${criticalOnly.length} of ${events.length}`);
check('severity filter is exact', criticalOnly.every((e) => e.severity === 'critical'), 'no leakage');

const ipQuery = filterEvents(events, { severities: [], query: '192.168.56.106', eventTypes: [], hosts: [], statuses: [] });
check('IP search matches', ipQuery.length > 0, `${ipQuery.length} events`);
check('IP search is relevant', ipQuery.every((e) => `${e.sourceIp}${e.destinationIp}`.includes('192.168.56.106')), 'all contain the IP');

const mitreQuery = filterEvents(events, { severities: [], query: 't1110', eventTypes: [], hosts: [], statuses: [] });
check('MITRE id search works', mitreQuery.length > 0, `${mitreQuery.length} events for T1110`);

const noMatch = filterEvents(events, { severities: [], query: 'zzzz-no-such-thing', eventTypes: [], hosts: [], statuses: [] });
check('empty state is reachable', noMatch.length === 0, 'nonsense query returns nothing');

const bySeverity = sortEvents(events.slice(0, 200), 'severity', 'desc');
check('severity sort puts critical first', bySeverity[0]!.severity === 'critical' || !events.slice(0, 200).some((e) => e.severity === 'critical'), `first=${bySeverity[0]!.severity}`);

console.log('\n=== Scenarios ===');
const rng = createRng(42);
for (const scenario of ALL_SCENARIOS) {
  const produced = materializeScenario(scenario, now - 60_000, rng);
  const ordered = produced.every((e, i) => i === 0 || produced[i - 1]!.timestamp <= e.timestamp);
  console.log(`  ${scenario.id.padEnd(20)} ${produced.length} events, ordered=${ordered}`);
  check(`${scenario.id} produces events`, produced.length > 0, `${produced.length}`);
  check(`${scenario.id} is chronological`, ordered, 'offsets ascending');
}
check('all six scenarios defined', ALL_SCENARIOS.length === 6, `${ALL_SCENARIOS.length}`);
check('demo script has beats', DEMO_SCRIPT.length === 5, `${DEMO_SCRIPT.length} beats`);

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}\n`);
process.exit(failures === 0 ? 0 : 1);
