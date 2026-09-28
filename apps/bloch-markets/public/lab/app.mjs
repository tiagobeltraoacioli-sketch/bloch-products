import {MAX_BYTES,parseReport,compareReports,coverageCsv,runPlan} from './model.mjs';
import {digest} from '../studio/receipt.mjs';

const $=id=>document.getElementById(id);
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const svg=(tag,attrs={})=>{const node=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [key,value]of Object.entries(attrs))node.setAttribute(key,value);return node;};
let catalog=null,current=null,baseline=null,selected=null,plan=null,busy=false;
let graphView={x:0,y:0,width:1000,height:550};
function updateGraphView(){const g=$('qualification-graph');g.setAttribute('viewBox',`${graphView.x} ${graphView.y} ${graphView.width} ${graphView.height}`);$('graph-zoom').textContent=Math.round(100000/graphView.width)+'%';}
function zoomGraph(factor){const width=Math.max(250,Math.min(1000,graphView.width/factor)),height=width*.55;graphView={x:graphView.x+(graphView.width-width)/2,y:graphView.y+(graphView.height-height)/2,width,height};updateGraphView();}
function resetGraph(){graphView={x:0,y:0,width:1000,height:550};updateGraphView();}
const status=(message,error=false)=>{$('lab-status').textContent=message;$('lab-status').dataset.error=String(error);};
function save(text,name,type='application/json'){const url=URL.createObjectURL(new Blob([text],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function allCases(){return catalog?.suites.flatMap(s=>s.cases.map(c=>({...c,suite:s.id,suite_title:s.title,status:current?.cases.find(r=>r.id===c.id)?.status??'unobserved'})))??[];}
function filteredCases(){const query=$('filter-search').value.toLowerCase().trim();return allCases().filter(c=>(!$('filter-suite').value||c.suite===$('filter-suite').value)&&(!$('filter-status').value||c.status===$('filter-status').value)&&(!query||[c.id,c.title,c.expectation,c.focus].join(' ').toLowerCase().includes(query)));}
function select(id){selected=id;renderGraph();renderCases();renderInspector();}

function renderGraph(){
  const graphic=$('qualification-graph');graphic.replaceChildren();if(!catalog)return;
  const cases=allCases(),visible=new Set(filteredCases().map(c=>c.id));
  const edge=(x,y,a,b)=>graphic.append(svg('path',{d:`M${x} ${y} H${(x+a)/2} V${b} H${a}`,class:'test-edge'}));
  const node=(x,y,width,label,note,attributes={})=>{
    const group=svg('g',{class:'test-node',...attributes});group.append(svg('rect',{x,y:y-23,width,height:46,rx:5}));
    const title=svg('text',{x:x+14,y:y-2});title.textContent=label;group.append(title);
    const detail=svg('text',{x:x+14,y:y+15,class:'test-node-note'});detail.textContent=note;group.append(detail);graphic.append(group);return group;
  };
  const positions=new Map(cases.map((c,i)=>[c.id,45+i*65]));
  for(const suite of catalog.suites){
    const y=suite.cases.reduce((sum,c)=>sum+positions.get(c.id),0)/suite.cases.length;
    edge(185,275,270,y);for(const c of suite.cases)edge(455,y,535,positions.get(c.id));
    const observed=current?.report.suites.find(s=>s.id===suite.id),state=!observed?'unobserved':observed.summary.failed?'failed':observed.summary.ignored?'ignored':'passed';
    node(270,y,185,{crypto_kernel:'Authorization kernel',native_pairs_crypto:'Atomic pair reference',native_pool_crypto:'Pool custody prototype'}[suite.id],observed?`${observed.summary.passed} / ${suite.cases.length} reported passed`:'No report loaded',{'data-state':state});
  }
  node(15,275,170,'Pinned Ustav source',catalog.revision.slice(0,12));
  for(const c of cases){const group=node(535,positions.get(c.id),450,c.title,`${c.focus} · ${c.status}`,{'data-state':c.status,'data-test':c.id,'data-selected':String(selected===c.id),'data-filtered':String(!visible.has(c.id)),tabindex:'0',role:'button','aria-label':`${c.title}, reported ${c.status}`});group.addEventListener('click',()=>select(c.id));group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();select(c.id);$('case-inspector').focus();}});}
}

function renderCases(){
  const cases=filteredCases();$('filter-count').textContent=`${cases.length} / ${allCases().length} named cases match the filters. The graph retains the full source context.`;
  $('case-list').innerHTML=cases.length?cases.map(c=>`<button type="button" class="case-entry" data-case="${c.id}" data-selected="${selected===c.id}"><span>${escape(c.title)}<small>${escape(c.suite_title)} · ${escape(c.focus)}</small></span><span class="case-state" data-state="${c.status}">${c.status.toUpperCase()}</span></button>`).join(''):'<p class="lab-help">No named case matches these filters.</p>';
  for(const button of $('case-list').querySelectorAll('[data-case]'))button.onclick=()=>select(button.dataset.case);
}

function renderInspector(){
  const c=allCases().find(c=>c.id===selected);if(!c){$('case-inspector').innerHTML='<p>No test selected.</p>';return;}
  const source=catalog.suites.find(s=>s.id===c.suite),suite=current?.report.suites.find(s=>s.id===c.suite);
  const url=catalog.repository+'/blob/'+catalog.revision+'/'+source.source_path;
  $('case-inspector').innerHTML=`<p class="eyebrow">${escape(c.focus.toUpperCase())} / PINNED TEST DEFINITION</p><h3>${escape(c.title)}</h3><span class="case-state" data-state="${c.status}">REPORTED ${c.status.toUpperCase()}</span><p>${escape(c.expectation)}</p><p>These are assertions in the pinned test, not an independent browser verification of the reported run.</p><a href="${escape(url)}" target="_blank" rel="noopener noreferrer">Inspect the pinned test source ↗</a><dl><dt>Named test</dt><dd>${escape(c.id)}</dd><dt>Suite</dt><dd>${escape(c.suite)}</dd><dt>Published test source SHA-256</dt><dd>${source.source_sha256}</dd><dt>Reported suite wall time</dt><dd>${suite?(suite.elapsed_ms/1000).toFixed(3)+' s · includes Cargo overhead':'Unavailable'}</dd><dt>Recorded standard-output SHA-256</dt><dd>${suite?suite.stdout_sha256:'Unavailable'}</dd></dl><p>Output hashes preserve a comparison reference; raw logs and verifiable run signatures are not included.</p>`;
}

function renderSummary(){
  const total=allCases().length,summary=current?.summary;
  $('lab-metrics').innerHTML=[['Reported passed',summary?.passed??'—',`${total} fixed named cases`],['Reported failed',summary?.failed??'—','Expected assertions did not complete'],['Reported ignored',summary?.ignored??'—','Ignored cases are not passes'],['Source claims',current?(current.pin_match?'MATCH':'DIFFER'):'—','Compared with the published pin']].map(([label,value,note])=>`<div><span>${label}</span><strong>${value}</strong><small>${note}</small></div>`).join('');
  $('suite-summary').innerHTML=(catalog?.suites??[]).map(s=>{const r=current?.report.suites.find(r=>r.id===s.id);let x=0;const segments=r?['passed','failed','ignored'].map(state=>{const width=r.summary[state]/s.cases.length*300,rect=`<rect x="${x}" y="0" width="${width}" height="20" fill="${{passed:'#a8ead2',failed:'#e8ac7b',ignored:'#a49ac9'}[state]}"/>`;x+=width;return rect;}).join(''):'<rect width="300" height="20" fill="#29414e"/>';return `<article class="suite-card"><p class="eyebrow">${escape(s.id.toUpperCase())}</p><h3>${escape(s.title)}</h3><strong>${r?r.summary.passed+' / '+s.cases.length:'No report'}</strong><svg viewBox="0 0 300 20" role="img" aria-label="${r?`${r.summary.passed} passed, ${r.summary.failed} failed, ${r.summary.ignored} ignored`:'No report'}">${segments}</svg><p>${r?`${r.summary.failed} failed · ${r.summary.ignored} ignored · exit ${r.exit_code}<br>${(r.elapsed_ms/1000).toFixed(3)} s wall time / ${r.harness_seconds} s harness`:'Open a report to inspect suite results.'}</p></article>`;}).join('');
  $('source-checks').innerHTML=current?current.checks.map(c=>`<tr><td>${escape(c.field)}</td><td>${escape(c.observed)}</td><td>${escape(c.expected)}</td><td class="${c.match?'check-yes':'check-no'}">${c.match?'Match':'Different'}</td></tr>`).join(''):'<tr><td colspan="4">No report loaded.</td></tr>';
  $('report-json').textContent=current?.original_text??'No report loaded.';$('report-hash').textContent=current?`Original file SHA-256: ${current.sha256} · run window ${current.report.started_at_utc} → ${current.report.finished_at_utc}`:'';
}

function renderComparison(){
  $('baseline-label').textContent=baseline?`Baseline: ${baseline.sha256.slice(0,16)}… · ${baseline.report.finished_at_utc} · ${baseline.summary.passed} / ${baseline.cases.length} reported passed`:'No baseline selected.';
  $('export-comparison').disabled=!baseline||!current;
  if(!baseline||!current){$('comparison').innerHTML='<p>Open a baseline and a current report to compare.</p>';return;}
  const comparison=compareReports(baseline,current),sourceChanges=comparison.source_fields.filter(c=>c.changed);
  $('comparison').innerHTML=`<p>${comparison.changes.filter(c=>c.changed).length} test outcome changes · ${sourceChanges.length} source claim changes. ${comparison.baseline_sha256===comparison.current_sha256?'Both selections contain the same report bytes.':''}</p><div class="table-scroll"><table><thead><tr><th>Named case</th><th>Baseline</th><th>Current</th></tr></thead><tbody>${comparison.changes.map(c=>`<tr class="${c.changed?'comparison-changed':''}"><td>${escape(c.title)}</td><td>${c.before}</td><td>${c.after}</td></tr>`).join('')}</tbody></table></div>${sourceChanges.length?`<div class="table-scroll"><table><thead><tr><th>Changed source field</th><th>Baseline</th><th>Current</th></tr></thead><tbody>${sourceChanges.map(c=>`<tr><td>${escape(c.field)}</td><td>${escape(c.before)}</td><td>${escape(c.after)}</td></tr>`).join('')}</tbody></table></div>`:''}<p>${escape(comparison.interpretation)}</p>`;
}

function render(){renderGraph();renderCases();renderInspector();renderSummary();renderComparison();for(const id of ['export-report','export-coverage','use-baseline'])$(id).disabled=!current||busy;$('clear-report').disabled=(!current&&!baseline)||busy;for(const id of ['load-example','report-import','baseline-import'])$(id).disabled=!catalog||busy;}

async function fetchText(path){const response=await fetch(path,{cache:'no-store',credentials:'omit',redirect:'error'});if(!response.ok)throw new Error(`Static evidence unavailable (HTTP ${response.status}).`);const reader=response.body.getReader(),chunks=[];let size=0;try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>MAX_BYTES){await reader.cancel();throw new Error('Published artifact exceeds 1 MiB.');}chunks.push(value);}}finally{reader.releaseLock();}const bytes=new Uint8Array(size);let at=0;for(const part of chunks){bytes.set(part,at);at+=part.length;}return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}
async function loadExample(){if(!catalog||busy)return;busy=true;render();try{const text=await fetchText('./example.json');if(await digest(text)!==catalog.example_sha256)throw new Error('Example file hash differs from the catalog.');const record=await parseReport(text,catalog);if(!record.pin_match)throw new Error('Published source claims differ from the catalog.');current=record;selected??=record.cases[0].id;status('Actual recorded local test run loaded. File hash and source claims checked; no signed run attestation is available.');}catch(error){status(error.message,true);}finally{busy=false;render();}}
async function importFile(event,asBaseline){const file=event.target.files[0];if(!file||!catalog||busy)return;busy=true;render();try{if(file.size>MAX_BYTES)throw new Error('Qualification files must be 1 MiB or smaller.');const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer()),record=await parseReport(text,catalog);if(asBaseline)baseline=record;else{current=record;selected??=record.cases[0].id;}status('Local report opened. Structure, named outcomes and source comparisons were recomputed.');}catch(error){status('Import rejected: '+error.message,true);}finally{event.target.value='';busy=false;render();}}
function prepare(){if(!catalog)return;try{plan=runPlan($('plan-path').value.trim(),$('plan-output').value.trim(),catalog);$('plan-command').textContent=plan.display_command;$('plan-note').textContent=plan.note;for(const id of ['copy-plan','download-plan'])$(id).disabled=false;}catch(error){plan=null;$('plan-command').textContent=error.message;for(const id of ['copy-plan','download-plan'])$(id).disabled=true;}}
$('load-example').onclick=loadExample;$('report-import').onchange=e=>importFile(e,false);$('baseline-import').onchange=e=>importFile(e,true);
for(const id of ['filter-suite','filter-status','filter-search'])$(id).addEventListener('input',()=>{renderGraph();renderCases();});
$('case-inspector').tabIndex=-1;
$('graph-zoom-in').onclick=()=>zoomGraph(1.25);$('graph-zoom-out').onclick=()=>zoomGraph(.8);$('graph-reset').onclick=resetGraph;
const graph=$('qualification-graph');let drag=null;
graph.addEventListener('pointerdown',e=>{if(e.button!==0||e.target.closest('[data-test]'))return;drag={id:e.pointerId,x:e.clientX,y:e.clientY,view:{...graphView},scale:graph.getScreenCTM().a};graph.setPointerCapture(e.pointerId);graph.dataset.dragging='true';});
graph.addEventListener('pointermove',e=>{if(!drag||e.pointerId!==drag.id)return;graphView={...drag.view,x:drag.view.x-(e.clientX-drag.x)/drag.scale,y:drag.view.y-(e.clientY-drag.y)/drag.scale};updateGraphView();});
for(const name of ['pointerup','pointercancel','lostpointercapture'])graph.addEventListener(name,()=>{drag=null;graph.dataset.dragging='false';});
graph.addEventListener('keydown',e=>{const step=graphView.width*.05;if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key)){e.preventDefault();if(e.key==='ArrowLeft')graphView.x-=step;if(e.key==='ArrowRight')graphView.x+=step;if(e.key==='ArrowUp')graphView.y-=step;if(e.key==='ArrowDown')graphView.y+=step;updateGraphView();}else if(e.key==='+'||e.key==='='){e.preventDefault();zoomGraph(1.25);}else if(e.key==='-'){e.preventDefault();zoomGraph(.8);}else if(e.key==='Home'){e.preventDefault();resetGraph();}});

$('clear-report').onclick=()=>{current=null;baseline=null;render();status('Local reports cleared. The pinned catalog remains available.');};
$('use-baseline').onclick=()=>{baseline=current;renderComparison();status('Current report kept as a local baseline. Open another report to compare.');};
$('export-report').onclick=()=>{if(current)save(current.original_text,'bloch-markets-qualification.json');};
$('export-coverage').onclick=()=>{if(current)save(coverageCsv(current),'bloch-markets-qualification.csv','text/csv');};
$('export-comparison').onclick=()=>{if(baseline&&current)save(JSON.stringify(compareReports(baseline,current),null,2),'bloch-markets-qualification-comparison.json');};
$('qualification-plan').onsubmit=e=>{e.preventDefault();prepare();};$('qualification-plan').oninput=()=>{plan=null;$('plan-command').textContent='Inputs changed. Prepare a new command.';for(const id of ['copy-plan','download-plan'])$(id).disabled=true;};
$('copy-plan').onclick=async()=>{if(!plan)return;try{await navigator.clipboard.writeText(plan.display_command);status('Command copied. Nothing was executed in this browser.');}catch{status('Clipboard unavailable. Copy the displayed command manually.',true);}};
$('download-plan').onclick=()=>{if(plan)save(JSON.stringify(plan,null,2),'bloch-markets-qualification-plan.json');};
async function init(){render();try{const source=JSON.parse(await fetchText('./catalog.json'));if(source.schema!=='bloch-markets-qualification-catalog/1'||source.repository!=='https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow'||!/^[a-f0-9]{40}$/.test(source.revision)||source.environment!=='local_sandbox_only'||source.chain_transaction!==false||source.production_finality!==false||!/^[a-f0-9]{64}$/.test(source.example_sha256)||source.example!=='./example.json')throw new Error('Unsupported test catalog.');const ids=['crypto_kernel','native_pairs_crypto','native_pool_crypto'];if(source.suites?.length!==3||source.suites.some((s,i)=>s.id!==ids[i]||s.source_path!==`crates/bloch-ustav/tests/${ids[i]}.rs`||!s.cases?.length||s.cases.some(c=>!/^[a-z0-9_]+$/.test(c.id))))throw new Error('Invalid named test catalog.');catalog=source;selected=allCases()[0]?.id;$('filter-suite').insertAdjacentHTML('beforeend',catalog.suites.map(s=>`<option value="${s.id}">${escape(s.title)}</option>`).join(''));$('qualification-plan').querySelector('button[type=submit]').disabled=false;prepare();await loadExample();}catch(error){status('Qualification Lab unavailable: '+error.message,true);}}
init();
