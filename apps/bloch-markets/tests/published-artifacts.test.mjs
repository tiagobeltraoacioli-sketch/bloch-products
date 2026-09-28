import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {digest, parseReceiptText} from '../public/studio/receipt.mjs';
import {parseReport} from '../public/lab/model.mjs';

const read = path => readFile(new URL('../public/' + path, import.meta.url), 'utf8');
const contract = JSON.parse(await read('studio/contract.json'));
const catalog = JSON.parse(await read('lab/catalog.json'));

test('published samples retain their original checksums and match the declared source', async () => {
  for (const [scenario, entry] of Object.entries(contract.scenarios)) {
    const text = await read('studio/' + entry.sample);
    assert.equal(await digest(text), entry.sample_sha256);
    const receipt = await parseReceiptText(text, contract);
    assert.equal(receipt.pin_match, true);
    assert.equal(receipt.scenario, scenario);
  }
  const text = await read('lab/example.json');
  assert.equal(await digest(text), catalog.example_sha256);
  const report = await parseReport(text, catalog);
  assert.equal(report.pin_match, true);
  assert.equal(report.all_passed, true);
});

test('Studio, Lab and capability status refer to the same protocol revision', async () => {
  const status = JSON.parse(await read('status.json'));
  for (const key of ['repository', 'revision', 'rust_toolchain', 'cargo_lock_sha256']) {
    assert.equal(contract[key], catalog[key]);
  }
  assert.equal(status.source.revision, contract.revision);
  assert.equal(status.qualification_lab.expected_named_cases, catalog.suites.reduce((sum, suite) => sum + suite.cases.length, 0));
  assert.equal(status.chain_connected, false);
  assert.equal(status.production_finality, false);
});
