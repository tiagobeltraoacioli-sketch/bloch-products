import {digest} from '../studio/receipt.mjs';
export const MAX_BYTES = 1024 * 1024;
const fail = message => { throw new Error(message); };
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const keys = (value, fields) => { if (!object(value) || Object.keys(value).length !== fields.length || fields.some(k=>!Object.hasOwn(value,k))) fail('Missing or unexpected report fields.'); };
const hash = (value,size=64) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${size}}$`).test(value);
const text = (value,max=250) => typeof value === 'string' && value.length>0 && value.length<=max && !/[\x00-\x1f\x7f]/.test(value);
const integer = (value,max) => Number.isSafeInteger(value) && value>=0 && value<=max;
const timestamp = value => {
  if (typeof value!=='string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(value) || !Number.isFinite(Date.parse(value))) fail('Invalid report timestamp.');
  const [year,month,day,hour,minute,second]=value.slice(0,19).split(/[-T:]/).map(Number);
  if(month<1||month>12||day<1||day>new Date(Date.UTC(year,month,0)).getUTCDate()||hour>23||minute>59||second>59)fail('Invalid report calendar date.');
  return Date.parse(value);
};

export function validateReport(raw,catalog) {
  keys(raw,['schema','environment','chain_transaction','production_finality','started_at_utc','finished_at_utc','provenance','suites']);
  if(raw.schema!=='bloch-markets-qualification/1'||raw.environment!=='local_sandbox_only'||raw.chain_transaction!==false||raw.production_finality!==false)fail('Only local qualification reports are accepted.');
  const start=timestamp(raw.started_at_utc),end=timestamp(raw.finished_at_utc);
  if(end<start||end-start>20*60*1000)fail('Inconsistent qualification time window.');
  const p=raw.provenance;
  keys(p,['repository','revision','rust_toolchain','cargo_lock_sha256','relevant_worktree_clean']);
  if(!text(p.repository)||!hash(p.revision,40)||!text(p.rust_toolchain,40)||!hash(p.cargo_lock_sha256)||p.relevant_worktree_clean!==true)fail('Invalid source provenance.');
  let url;try{url=new URL(p.repository);}catch{fail('Invalid repository URL.');}
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash)fail('Repository must be a plain HTTPS URL.');
  if(!Array.isArray(raw.suites)||raw.suites.length!==catalog.suites.length)fail('The report must contain every catalog suite.');
  const seen=new Set();
  for(const suite of raw.suites){
    keys(suite,['id','source_sha256','command','cases','summary','exit_code','elapsed_ms','harness_seconds','stdout_sha256','stderr_sha256']);
    const expected=catalog.suites.find(s=>s.id===suite.id);
    if(!expected||seen.has(suite.id))fail('Unknown or duplicate suite.');seen.add(suite.id);
    if(!hash(suite.source_sha256)||!hash(suite.stdout_sha256)||!hash(suite.stderr_sha256)||!integer(suite.elapsed_ms,305000)||!Number.isFinite(suite.harness_seconds)||suite.harness_seconds<0||suite.harness_seconds>300||suite.harness_seconds*1000>suite.elapsed_ms+1000)fail('Invalid suite evidence or duration.');
    if(!Array.isArray(suite.command)||suite.command.length<1||suite.command.length>25||suite.command.some(v=>!text(v)))fail('Invalid recorded command.');
    keys(suite.summary,['passed','failed','ignored']);
    if(!Array.isArray(suite.cases)||suite.cases.length!==expected.cases.length)fail('Incomplete test coverage.');
    const cases=new Set(),counts={passed:0,failed:0,ignored:0};
    for(const c of suite.cases){keys(c,['id','status']);if(!expected.cases.some(e=>e.id===c.id)||cases.has(c.id)||typeof c.status!=='string'||!Object.hasOwn(counts,c.status))fail('Unknown, duplicate or invalid test result.');cases.add(c.id);counts[c.status]++;}
    if(Object.keys(counts).some(k=>suite.summary[k]!==counts[k])||suite.exit_code!==(counts.failed?101:0))fail('Suite summary or exit code disagrees with test results.');
  }
  return structuredClone(raw);
}

export function assess(raw,catalog) {
  const report=validateReport(raw,catalog),p=report.provenance;
  const checks=['repository','revision','rust_toolchain','cargo_lock_sha256'].map(key=>({field:key,observed:p[key],expected:catalog[key],match:p[key]===catalog[key]}));
  const cases=[];
  for(const suite of report.suites){
    const expected=catalog.suites.find(s=>s.id===suite.id);
    for(const key of ['source_sha256','command']){const observed=key==='command'?JSON.stringify(suite[key]):suite[key],target=key==='command'?JSON.stringify(expected[key]):expected[key];checks.push({field:suite.id+'.'+key,observed,expected:target,match:observed===target});}
    for(const meta of expected.cases){const result=suite.cases.find(c=>c.id===meta.id);cases.push({...meta,suite:suite.id,suite_title:expected.title,status:result.status});}
  }
  const summary=Object.fromEntries(['passed','failed','ignored'].map(state=>[state,cases.filter(c=>c.status===state).length]));
  return {report,checks,cases,summary,pin_match:checks.every(c=>c.match),all_passed:summary.passed===cases.length};
}

export async function parseReport(text,catalog) {
  if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>MAX_BYTES)fail('Qualification files must be 1 MiB or smaller.');
  let raw;try{raw=JSON.parse(text);}catch{fail('The qualification file is not valid JSON.');}
  return {...assess(raw,catalog),original_text:text,sha256:await digest(text)};
}

export function compareReports(baseline,current) {
  const changes=current.cases.map(c=>{const before=baseline.cases.find(b=>b.id===c.id&&b.suite===c.suite);return {suite:c.suite,id:c.id,title:c.title,before:before.status,after:c.status,changed:before.status!==c.status};});
  const source_fields=current.checks.map(c=>{const b=baseline.checks.find(b=>b.field===c.field);return {field:c.field,before:b.observed,after:c.observed,changed:b.observed!==c.observed};});
  return {schema:'bloch-markets-qualification-comparison/1',baseline_sha256:baseline.sha256,current_sha256:current.sha256,
    chain_transaction:false,production_finality:false,changes,source_fields,
    interpretation:'Unsigned local reports; changes are reported outcomes, not independently verified execution. Elapsed times include compilation and are not comparable performance benchmarks.'};
}

export function coverageCsv(record) {
  const rows=[['suite','test','focus','reported_status','claimed_source_matches','chain_transaction','production_finality'],...record.cases.map(c=>[c.suite,c.id,c.focus,c.status,record.pin_match,false,false])];
  return rows.map(row=>row.map(value=>{const s=String(value);return '"'+(/^[\s]*[=+\-@]/.test(s)?"'":'')+s.replaceAll('"','""')+'"';}).join(',')).join('\r\n');
}

export function runPlan(path,output,catalog) {
  if(!text(path,240)||!text(output,160)||path.startsWith('-')||output.startsWith('-'))fail('Enter valid local paths.');
  const command=['python3','sandbox/qualify.py','--protocol-repo',path,'--output',output];
  return {schema:'bloch-markets-qualification-plan/1',chain_transaction:false,production_finality:false,
    source_revision:catalog.revision,command,display_command:command.map(s=>"'"+s.replaceAll("'","'\"'\"'")+"'").join(' '),
    note:'Run from the Bloch Markets repository with the pinned clean checkout, Rust toolchain and cached dependencies. Uses public upstream test fixtures, never production keys. The browser does not execute this command.'};
}
