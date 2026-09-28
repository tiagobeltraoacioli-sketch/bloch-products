import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {assess, parseReport, validateReport} from '../public/lab/model.mjs';

const load = path => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const catalog = load('../public/lab/catalog.json');
const example = load('../public/lab/example.json');

test('the published report accounts for all eight named cases', () => {
  const result = assess(example, catalog);
  assert.equal(result.cases.length, 8);
  assert.deepEqual(result.summary, {passed: 8, failed: 0, ignored: 0});
  assert.equal(result.all_passed, true);
  assert.equal(result.pin_match, true);
});

for (const status of ['passed', 'failed', 'ignored']) {
  test(`a ${status} string remains a supported reported outcome`, () => {
    const report = structuredClone(example);
    const suite = report.suites[0];
    suite.cases[0].status = status;
    if (status !== 'passed') {
      suite.summary.passed--;
      suite.summary[status]++;
      suite.exit_code = status === 'failed' ? 101 : 0;
    }
    const result = assess(report, catalog);
    assert.equal(Object.values(result.summary).reduce((a, b) => a + b, 0), 8);
    assert.equal(result.cases.find(c => c.id === suite.cases[0].id).status, status);
    assert.equal(result.all_passed, status === 'passed');
  });

  test(`JSON arrays cannot masquerade as the ${status} outcome`, async () => {
    const report = structuredClone(example);
    const suite = report.suites[0];
    suite.cases[0].status = [status];
    if (status !== 'passed') {
      suite.summary.passed--;
      suite.summary[status]++;
      suite.exit_code = status === 'failed' ? 101 : 0;
    }
    assert.throws(() => validateReport(report, catalog), /invalid test result/);
    await assert.rejects(parseReport(JSON.stringify(report), catalog), /invalid test result/);
  });
}

test('nested arrays cannot masquerade as a passed result', () => {
  const report = structuredClone(example);
  report.suites[0].cases[0].status = [[['passed']]];
  assert.throws(() => validateReport(report, catalog), /invalid test result/);
});

test('missing, unknown and non-string outcomes are rejected', () => {
  for (const value of [null, true, false, 0, 1, {}, [], 'PASS', '', '__proto__', 'constructor']) {
    const report = structuredClone(example);
    report.suites[0].cases[0].status = value;
    assert.throws(() => validateReport(report, catalog));
  }
  const missing = structuredClone(example);
  delete missing.suites[0].cases[0].status;
  assert.throws(() => validateReport(missing, catalog));
});

test('valid imports still reject contradictory suite totals', async () => {
  const report = structuredClone(example);
  report.suites[0].summary.passed--;
  await assert.rejects(parseReport(JSON.stringify(report), catalog), /disagrees with test results/);
});

test('a source mismatch remains inspectable without claiming a matching pin', () => {
  const report = structuredClone(example);
  report.provenance.revision = '0'.repeat(40);
  const result = assess(report, catalog);
  assert.equal(result.pin_match, false);
  assert.deepEqual(result.summary, {passed: 8, failed: 0, ignored: 0});
});
