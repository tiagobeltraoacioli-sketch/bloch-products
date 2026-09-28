#!/usr/bin/env node
// Offline inspection of unsigned local evidence using the same validators as the site.
import {constants} from 'node:fs';
import {open, readFile} from 'node:fs/promises';
import {parseReceiptText, parseReview} from '../public/studio/receipt.mjs';
import {parseReport} from '../public/lab/model.mjs';

const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const MAX_FILES = 12;
const help = `Usage: npm run inspect -- FILE.json [FILE.json ...]

Inspect local lifecycle receipts, native-pair receipts, Studio review bundles
and Qualification Lab reports. No network access or kernel execution.
At most 12 regular files and 16 MiB in total; original per-artifact limits apply.

Outputs one JSON assessment after every input has been validated.
Exit 0: all source claims match; all included qualification cases report passed.
Exit 2: valid evidence contains source differences, failed cases or ignored cases.
Exit 1: invalid evidence, unreadable inputs or incorrect command usage.
Use -- before a filename beginning with a dash.
These results are not signed run attestations or production qualification.
`;

async function readBounded(path, remaining) {
  const flags = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0);
  const handle = await open(path, flags);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Evidence inputs must be regular files.');
    if (stat.size > remaining) throw new Error('Evidence inputs exceed the 16 MiB total limit.');
    const buffer = Buffer.alloc(remaining + 1);
    let length = 0;
    while (length < buffer.length) {
      const {bytesRead} = await handle.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > remaining) throw new Error('Evidence inputs exceed the 16 MiB total limit.');
    return {
      text: new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(buffer.subarray(0, length)),
      bytes: length,
    };
  } finally {
    await handle.close();
  }
}

const indexReceipt = record => ({
  sha256: record.sha256,
  scenario: record.scenario,
  claimed_source_matches: record.pin_match,
  differing_fields: record.checks.filter(check => !check.match).map(check => check.name),
});

async function main(args) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
    process.stdout.write(help);
    return;
  }
  const files = [];
  let positional = false;
  for (const arg of args) {
    if (!positional && arg === '--') positional = true;
    else if (!positional && arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else files.push(arg);
  }
  if (!files.length || files.length > MAX_FILES) throw new Error('Supply 1–12 JSON files; use --help for usage.');

  const contract = JSON.parse(await readFile(new URL('../public/studio/contract.json', import.meta.url), 'utf8'));
  const catalog = JSON.parse(await readFile(new URL('../public/lab/catalog.json', import.meta.url), 'utf8'));
  for (const key of ['repository', 'revision', 'rust_toolchain', 'cargo_lock_sha256']) {
    if (contract[key] !== catalog[key]) throw new Error('The Studio and Lab source pins disagree.');
  }

  const entries = [];
  let bytes = 0;
  for (const file of files) {
    const input = await readBounded(file, MAX_INPUT_BYTES - bytes);
    bytes += input.bytes;
    let raw;
    try { raw = JSON.parse(input.text); }
    catch { throw new Error('An input is not valid JSON.'); }

    if (raw?.schema === 'bloch-markets-qualification/1') {
      const record = await parseReport(input.text, catalog);
      entries.push({
        file,
        kind: 'qualification',
        sha256: record.sha256,
        claimed_source_matches: record.pin_match,
        differing_fields: record.checks.filter(check => !check.match).map(check => check.field),
        reported_outcomes: record.summary,
        all_reported_passed: record.all_passed,
      });
    } else {
      const records = raw?.schema === 'bloch-markets-receipt-review/1'
        ? await parseReview(raw, contract)
        : [await parseReceiptText(input.text, contract)];
      entries.push({
        file,
        kind: raw?.schema === 'bloch-markets-receipt-review/1' ? 'receipt_review' : 'receipt',
        claimed_source_matches: records.every(record => record.pin_match),
        records: records.map(indexReceipt),
      });
    }
  }
  const attention = entries.some(entry => !entry.claimed_source_matches || entry.all_reported_passed === false);
  process.stdout.write(JSON.stringify({
    schema: 'bloch-markets-evidence-inspection/1',
    source_revision: contract.revision,
    chain_connected: false,
    production_finality: false,
    run_attestation: false,
    needs_review: attention,
    entries,
    interpretation: 'Structure and claimed source comparisons only. No independent proof of execution, chain activation or asset backing.',
  }, null, 2) + '\n');
  process.exitCode = attention ? 2 : 0;
}

try {
  await main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`Inspection rejected: ${error.message}\n`);
  process.exitCode = 1;
}
