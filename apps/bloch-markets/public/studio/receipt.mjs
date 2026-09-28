// Receipt structure and claimed provenance checks, not cryptographic run attestation.
export const MAX_RECEIPTS=12,MAX_RECEIPT_BYTES=1024*1024;
const fail=message=>{throw new Error(message);};
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const keys=(value,expected,name)=>{if(!obj(value)||Object.keys(value).length!==expected.length||expected.some(k=>!Object.hasOwn(value,k)))fail(`Unexpected or missing ${name} fields.`);};
const hash=(v,size)=>typeof v==='string'&&new RegExp(`^[a-f0-9]{${size}}$`).test(v);
const text=(v,max)=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\x00-\x1f\x7f]/.test(v);
export function validateReceipt(raw){
  keys(raw,['schema_version','receipt_kind','environment','chain_transaction','production_finality','generated_at_utc','provenance','result'],'receipt');
  if(raw.schema_version!==1||raw.environment!=='local_sandbox_only'||raw.chain_transaction!==false||raw.production_finality!==false)fail('Only version-one local sandbox receipts are supported. Chain and production-finality claims are rejected.');
  const scenario=raw.receipt_kind==='local_ustav_reference_run'?'lifecycle':raw.receipt_kind==='local_ustav_pair_reference_run'?'native_pair':fail('Unsupported receipt kind.');
  if(!text(raw.generated_at_utc,40)||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(raw.generated_at_utc)||!Number.isFinite(Date.parse(raw.generated_at_utc)))fail('Invalid generation timestamp.');
  const [year,month,day,hour,minute,second]=raw.generated_at_utc.slice(0,19).split(/[-T:]/).map(Number);const days=new Date(Date.UTC(year,month,0)).getUTCDate();if(month<1||month>12||day<1||day>days||hour>23||minute>59||second>59)fail('Invalid calendar timestamp.');
  const p=raw.provenance;keys(p,['repository','revision','rust_toolchain','command','cargo_lock_sha256','example_sha256','relevant_worktree_clean'],'provenance');
  if(!text(p.repository,240)||!hash(p.revision,40)||!text(p.rust_toolchain,40)||!hash(p.cargo_lock_sha256,64)||!hash(p.example_sha256,64)||p.relevant_worktree_clean!==true||!Array.isArray(p.command)||p.command.length<1||p.command.length>20||p.command.some(s=>!text(s,250)))fail('Invalid receipt provenance.');
  let url;try{url=new URL(p.repository);}catch{fail('Invalid source repository URL.');}if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash)fail('Source repository must use a plain HTTPS URL.');
  const r=raw.result;
  if(scenario==='lifecycle'){
    keys(r,['asset_id','mint_supply','transfer_supply','final_supply','spent_input_replay_rejected','local_snapshot_restored','final_local_state_root'],'lifecycle result');
    if(!hash(r.asset_id,64)||!hash(r.final_local_state_root,64)||r.mint_supply!==60||r.transfer_supply!==60||r.final_supply!==0||r.spent_input_replay_rejected!==true||r.local_snapshot_restored!==true)fail('Receipt does not match the v1 lifecycle result contract.');
  }else{
    keys(r,['independently_owned_assets','joint_hybrid_owner_authorization','atomic_local_settlement','spent_input_replay_rejected','illustrative_asset_only','backing_or_redemption_implemented'],'pair result');
    if(r.independently_owned_assets!==2||r.joint_hybrid_owner_authorization!==true||r.atomic_local_settlement!==true||r.spent_input_replay_rejected!==true||r.illustrative_asset_only!==true||r.backing_or_redemption_implemented!==false)fail('Receipt does not match the v1 native-pair result contract.');
  }
  return {scenario,receipt:structuredClone(raw)};
}
export function assess(raw,contract){
  const {scenario,receipt}=validateReceipt(raw),p=receipt.provenance,expected=contract.scenarios[scenario];
  const checks=[['Repository',p.repository,contract.repository],['Protocol revision',p.revision,contract.revision],['Rust toolchain',p.rust_toolchain,contract.rust_toolchain],['Cargo lock SHA-256',p.cargo_lock_sha256,contract.cargo_lock_sha256],['Example SHA-256',p.example_sha256,expected.example_sha256],['Executed command',JSON.stringify(p.command),JSON.stringify(expected.command)]];
  return {scenario,receipt,pin_match:checks.every(([,value,target])=>value===target),checks:checks.map(([name,observed,expected])=>({name,observed,expected,match:observed===expected})),limitations:'The browser checks structure, fixed result values and claimed source metadata. Receipts contain no independently verifiable run signature; no chain transaction, finality or asset backing is established.'};
}
export async function digest(text){const bytes=new TextEncoder().encode(text);return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');}
export async function parseReceiptText(text,contract){if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>MAX_RECEIPT_BYTES)fail('Each receipt must be 1 MiB or smaller.');let raw;try{raw=JSON.parse(text);}catch{fail('The file is not valid JSON.');}return {...assess(raw,contract),sha256:await digest(text),original_text:text};}
export function compare(a,b){
  const one=a.receipt,two=b.receipt,rows=[];
  for(const [name,key]of [['Protocol revision','revision'],['Cargo lock','cargo_lock_sha256'],['Example source','example_sha256'],['Toolchain','rust_toolchain']])rows.push({name,a:one.provenance[key],b:two.provenance[key],equal:one.provenance[key]===two.provenance[key]});
  if(a.scenario===b.scenario)for(const key of Object.keys(one.result))rows.push({name:key,a:one.result[key],b:two.result[key],equal:one.result[key]===two.result[key]});
  return {sameScenario:a.scenario===b.scenario,rows,note:'Asset identifiers and local state roots can differ across lifecycle runs because the example generates fresh ephemeral keys. Differences are not evidence of a chain reorganization.'};
}
export function report(records){return {schema:'bloch-markets-receipt-review/1',generated_at_utc:new Date().toISOString(),chain_connected:false,production_finality:false,verification:'local structure and claimed provenance only; not a signed attestation',records:records.map(r=>({sha256:r.sha256,original_text:r.original_text,checks:r.checks,pin_match:r.pin_match}))};}
export async function parseReview(raw,contract){
  if(raw?.schema!=='bloch-markets-receipt-review/1'||raw.chain_connected!==false||raw.production_finality!==false||!Array.isArray(raw.records)||raw.records.length<1||raw.records.length>MAX_RECEIPTS)fail('Unsupported review bundle.');
  const result=[];for(const entry of raw.records){if(!hash(entry?.sha256,64))fail('Invalid file checksum.');const parsed=await parseReceiptText(entry.original_text,contract);if(parsed.sha256!==entry.sha256)fail('Receipt bytes do not match the saved file checksum.');result.push(parsed);}return result;
}
export function csv(records){const rows=[['file_sha256','scenario','generation_time','revision','claimed_source_matches','asset_id','mint_supply','transfer_supply','final_supply','local_state_root','chain_transaction','production_finality'],...records.map(r=>[r.sha256,r.scenario,r.receipt.generated_at_utc,r.receipt.provenance.revision,r.pin_match,r.receipt.result.asset_id??'',r.receipt.result.mint_supply??'',r.receipt.result.transfer_supply??'',r.receipt.result.final_supply??'',r.receipt.result.final_local_state_root??'',false,false])];return rows.map(row=>row.map(v=>{const s=String(v);return '"'+(/^[\s]*[=+\-@]/.test(s)?"'":'')+s.replaceAll('"','""')+'"';}).join(',')).join('\r\n');}
export function runPlan(scenario,protocolPath,output,contract){
  if(!Object.hasOwn(contract.scenarios,scenario)||!text(protocolPath,240)||!text(output,160)||output.startsWith('-'))fail('Choose a scenario and valid local paths.');
  const args=['python3','sandbox/run.py','--protocol-repo',protocolPath,'--scenario',scenario,'--output',output],quote=s=>"'"+s.replaceAll("'","'\"'\"'")+"'";
  return {schema:'bloch-markets-local-run-plan/1',execution_mode:'local_reference',chain_connected:false,production_finality:false,source_revision:contract.revision,scenario,command:args,display_command:args.map(quote).join(' '),prerequisites:['Clean local protocol checkout at the pinned revision','Rust '+contract.rust_toolchain+' and cached dependencies','Run from the Bloch Markets repository; output file must not already exist'],note:'This plan does not execute code, create an asset on-chain or request keys.'};
}
