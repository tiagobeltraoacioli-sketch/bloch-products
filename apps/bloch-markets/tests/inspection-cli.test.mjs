import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {after, test} from 'node:test';
import {parseReceiptText, report} from '../public/studio/receipt.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const scratch = mkdtempSync(join(tmpdir(), 'bloch-markets-inspection-'));
after(() => rmSync(scratch, {recursive: true, force: true}));
const load = path => JSON.parse(readFileSync(join(root, path), 'utf8'));
const run = (...args) => spawnSync(process.execPath, [join(root, 'scripts/inspect.mjs'), ...args], {
  cwd: root, encoding: 'utf8', timeout: 10000,
});
const fixture = (name, value) => {
  const path = join(scratch, name);
  writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
  return path;
};

test('inspects lifecycle, pair and qualification files in one offline assessment', () => {
  const result = run('public/studio/examples/lifecycle.json', 'public/studio/examples/native-pair.json', 'public/lab/example.json');
  assert.equal(result.status, 0, result.stderr);
  const assessment = JSON.parse(result.stdout);
  assert.equal(assessment.entries.length, 3);
  assert.equal(assessment.needs_review, false);
  assert.equal(assessment.run_attestation, false);
  assert.equal(assessment.chain_connected, false);
  assert.equal(assessment.production_finality, false);
  assert.deepEqual(assessment.entries[2].reported_outcomes, {passed: 8, failed: 0, ignored: 0});
});

test('recomputes saved review claims and rejects corrupted receipt bytes', async () => {
  const contract = load('public/studio/contract.json');
  const receipt = load('public/studio/examples/lifecycle.json');
  receipt.provenance.revision = '0'.repeat(40);
  const record = await parseReceiptText(JSON.stringify(receipt), contract);
  const bundle = report([record]);
  bundle.records[0].pin_match = true;
  bundle.records[0].checks = [];
  let result = run(fixture('review.json', bundle));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).entries[0].records[0].claimed_source_matches, false);
  bundle.records[0].original_text += '\n';
  result = run(fixture('corrupt-review.json', bundle));
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /checksum/);
});

for (const status of ['failed', 'ignored']) {
  test(`complete ${status} outcomes return review exit status without rejecting the report`, () => {
    const report = load('public/lab/example.json');
    report.suites[0].cases[0].status = status;
    report.suites[0].summary.passed--;
    report.suites[0].summary[status]++;
    report.suites[0].exit_code = status === 'failed' ? 101 : 0;
    const result = run(fixture(`${status}.json`, report));
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stdout).entries[0].reported_outcomes[status], 1);
  });
}

test('rejects the malformed-status regression without emitting a partial assessment', () => {
  const report = load('public/lab/example.json');
  report.suites[0].cases[0].status = ['passed'];
  const result = run('public/studio/examples/lifecycle.json', fixture('invalid.json', report));
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /invalid test result/);
});

test('source differences produce inspectable results and exit status 2', () => {
  const report = load('public/lab/example.json');
  report.provenance.revision = '0'.repeat(40);
  const result = run(fixture('different-source.json', report));
  assert.equal(result.status, 2, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout).entries[0].differing_fields, ['revision']);
});

test('rejects excessive file counts, oversized inputs, directories and invalid UTF-8', () => {
  assert.equal(run().status, 1);
  assert.equal(run(...Array(13).fill('public/lab/example.json')).status, 1);
  assert.equal(run(scratch).status, 1);
  const big = join(scratch, 'oversized.json');
  writeFileSync(big, Buffer.alloc(16 * 1024 * 1024 + 1, 32));
  assert.match(run(big).stderr, /16 MiB/);
  const binary = join(scratch, 'invalid-utf8.json');
  writeFileSync(binary, Buffer.from([0xc3, 0x28]));
  assert.equal(run(binary).status, 1);
});

test('symlink evidence files are refused on Unix', {skip: process.platform === 'win32'}, () => {
  const link = join(scratch, 'linked-report.json');
  symlinkSync(join(root, 'public/lab/example.json'), link);
  assert.equal(run(link).status, 1);
});

test('help succeeds without inspecting an input', () => {
  const result = run('--help');
  assert.equal(result.status, 0);
  assert.match(result.stdout, /No network access/);
});
