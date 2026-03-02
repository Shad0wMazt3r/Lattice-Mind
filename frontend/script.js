'use strict';
//  globals 
let currentRunId = null;
let ws = null;
let _allHistoryRows = [];
let _allRules = [];

//  utils 
const $= id => document.getElementById(id);
const fmtDur = (a,b) => {
  if(!a) return '';
  const ms = new Date(b||new Date()) - new Date(a);
  return ms<1000 ? ms+'ms' : (ms/1000).toFixed(1)+'s';
};
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

//  dir-scan feature flag toggle ──────────────────────────────────────────────
let _dirScanEnabled = false;

async function _loadSettings(){
  try{
    const r = await fetch('/settings');
    if(!r.ok) return;
    const d = await r.json();
    _dirScanEnabled = !!d.dir_scan_enabled;
    _renderDirScanBadge();
  }catch(e){}
}

function _renderDirScanBadge(){
  const dot = $('dirscan-dot');
  const wrap = $('hdr-dirscan-toggle');
  if(!dot||!wrap) return;
  if(_dirScanEnabled){
    dot.className = 'flag-dot flag-dot-on';
    wrap.title = 'Directory scanning ON — click to disable';
  } else {
    dot.className = 'flag-dot flag-dot-off';
    wrap.title = 'Directory scanning OFF — click to enable';
  }
}

async function toggleDirScan(){
  _dirScanEnabled = !_dirScanEnabled;
  _renderDirScanBadge();
  try{
    await fetch('/settings',{
      method:'PUT',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({dir_scan_enabled: _dirScanEnabled})
    });
  }catch(e){ /* revert on failure */ _dirScanEnabled=!_dirScanEnabled; _renderDirScanBadge(); }
}

_loadSettings();



//  tab switching ─
function switchTab(name){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  $('tab-'+name).classList.add('active');
  // find matching button by onclick
  document.querySelectorAll('.tab-btn').forEach(b=>{
    if(b.getAttribute('onclick') && b.getAttribute('onclick').includes("'"+name+"'"))
      b.classList.add('active');
  });
  if(name==='history') loadHistory();
  if(name==='rules') loadRules();
}

//  type change 
function onTypeChange(){
  const t = $('ch-type').value;
  const web = ['web','osint','network','misc'];
  const bin = ['pwn','forensics','steganography','reverse_engineering'];
  $('field-url').classList.toggle('hidden', !web.includes(t));
  $('field-filepath').classList.toggle('hidden', !bin.includes(t));
  $('field-upload').classList.toggle('hidden', !bin.includes(t));
  $('field-crypto-text').classList.toggle('hidden', t!=='crypto');
}
onTypeChange();

//  submit challenge ─
async function submitChallenge(){
  const btn = $('solve-btn');
  btn.disabled = true;

  let filePath = $('ch-filepath').value||null;
  // handle file upload first if file selected
  const fileInput = $('ch-upload');
  if(fileInput && fileInput.files && fileInput.files[0]){
    try{
      const fd = new FormData();
      fd.append('file', fileInput.files[0]);
      const up = await fetch('/upload',{method:'POST',body:fd});
      if(!up.ok) throw new Error('Upload failed: '+await up.text());
      const upData = await up.json();
      filePath = upData.path;
    }catch(e){
      alert('File upload error: '+e.message);
      btn.disabled=false; return;
    }
  }

  const body = {
    name: $('ch-name').value||'Untitled',
    challenge_type: $('ch-type').value,
    url: $('ch-url').value||null,
    file_path: filePath,
    flag_format: $('ch-flagfmt').value||'flag{',
    metadata: {}
  };
  // include crypto text in metadata if provided
  const ct = $('ch-crypto-text').value.trim();
  if(ct) body.metadata.crypto_text = ct;

  try{
    const r = await fetch('/solve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok) throw new Error(await r.text());
    const data = await r.json();
    currentRunId = data.run_id;
    switchTab('active');
    connectWebSocket(currentRunId);
    loadRecentRuns();
  }catch(e){
    alert('Error: '+e.message);
  }finally{
    btn.disabled=false;
  }
}

//  WebSockets 
function connectWebSocket(runId){
  if(ws) ws.close();
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${window.location.host}/ws/${runId}`);
  
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'init' || msg.type === 'update') {
      updateActiveRunUI(msg.data);
    } else if (msg.type === 'step') {
      fetchRunState(runId);
    }
  };

  ws.onclose = () => {
    console.log('WebSocket closed');
  };
}

async function fetchRunState(runId) {
  try {
    const r = await fetch('/runs/' + runId);
    if (!r.ok) return;
    const data = await r.json();
    updateActiveRunUI(data);
  } catch (e) {}
}

//  active run UI ─
function updateActiveRunUI(run){
  // status bar
  const badge = $('run-status-badge');
  badge.className = 'status-badge '+(run.status||'idle');
  badge.textContent = (run.status||'idle').toUpperCase();
  $('run-id-display').textContent = run.run_id ? run.run_id.slice(0,8) : '';

  const ch = run.challenge||{};
  const target = ch.url || ch.file_path || ch.name || '';
  $('run-target').textContent = target ? (' '+target) : '';

  if(run.flag){
    $('flag-banner').classList.add('visible');
    $('flag-banner-text').textContent = run.flag;
  } else {
    $('flag-banner').classList.remove('visible');
  }

  // tree + terminal
  if(run.steps && run.steps.length){
    const nodesMap = buildTreeFromSteps(run.steps);
    const laid = layoutTree(nodesMap);
    renderTree(laid);
    // terminal: last 50 lines
    const lines = run.steps.slice(-50);
    $('terminal-out').innerHTML = lines.map(s=>{
      const cls = s.event==='flag_found'?'flag_found':(s.event==='node_end'?'node_end '+(s.status||''):'node_start');
      const ts = (s.timestamp||'').slice(11,19);
      const msg = s.event==='node_start' ? '[START] '+s.node_name
                : s.event==='flag_found' ? '[FLAG!] '+JSON.stringify(s.data)
                : '[END]   '+s.node_name+'  '+(s.status||'?');
      return '<div class="term-line '+cls+'">'+esc(ts)+' '+esc(msg)+'</div>';
    }).join('');
    $('terminal-out').scrollTop = $('terminal-out').scrollHeight;
  }

  // confidence display
  renderConfidence(run.confidence || {});
  // observations display
  renderObservations(run.observations || {});
}

//  tree builder ─
function buildTreeFromSteps(steps){
  const nodes = {};
  const rootIds = [];

  for(const s of steps){
    if(s.event==='node_start'){
      if(!nodes[s.node_id]){
        nodes[s.node_id] = {
          id: s.node_id, name: s.node_name||s.node_id,
          status: 'running', data: {}, children: [],
          parent_id: s.parent_node_id, timestamp: s.timestamp
        };
        if(s.parent_node_id && nodes[s.parent_node_id]){
          if (!nodes[s.parent_node_id].children.includes(s.node_id)) {
            nodes[s.parent_node_id].children.push(s.node_id);
          }
        } else {
          rootIds.push(s.node_id);
        }
      }
    } else if(s.event==='node_end' && nodes[s.node_id]){
      nodes[s.node_id].status = s.status||'success';
      nodes[s.node_id].data = s.data||{};
      nodes[s.node_id].error = s.error||null;
      nodes[s.node_id].next_node = s.next_node||null;
    } else if(s.event==='flag_found'){
      if(nodes[s.node_id]) nodes[s.node_id].status='flag_found';
    }
  }
  return {nodes, rootIds};
}

//  tree layout ─
const NODE_W=170, NODE_H=44, H_GAP=30, V_GAP=60;

function layoutTree({nodes, rootIds}){
  if(!rootIds.length) return {nodes, rootIds, width:600, height:400};
  // assign positions using simple BFS level layout
  const levels = {};
  const queue = rootIds.map(id=>({id,depth:0}));
  const visited = new Set();
  while(queue.length){
    const {id,depth} = queue.shift();
    if(visited.has(id)) continue;
    visited.add(id);
    if(!levels[depth]) levels[depth]=[];
    levels[depth].push(id);
    (nodes[id]?.children||[]).forEach(cid=>queue.push({id:cid,depth:depth+1}));
  }
  const depthCount = Object.keys(levels).length;
  const maxWidth = Math.max(...Object.values(levels).map(a=>a.length));
  const totalW = Math.max(600, maxWidth*(NODE_W+H_GAP)+H_GAP);
  const totalH = depthCount*(NODE_H+V_GAP)+V_GAP;

  for(const [depth, ids] of Object.entries(levels)){
    const d = parseInt(depth);
    const rowW = ids.length*(NODE_W+H_GAP)-H_GAP;
    const startX = (totalW-rowW)/2;
    ids.forEach((id,i)=>{
      if(nodes[id]){
        nodes[id].x = startX + i*(NODE_W+H_GAP);
        nodes[id].y = V_GAP + d*(NODE_H+V_GAP);
      }
    });
  }
  return {nodes, rootIds, width: totalW, height: Math.max(400, totalH)};
}

//  tree renderer 
const STATUS_COLOR = {
  running: '#ffd700', success: '#39ff14', completed: '#39ff14',
  failure: '#ff3333', error: '#ff3333', flag_found: '#39ff14',
  default: '#444'
};
const STATUS_FILL = {
  success:'#001a00', completed:'#001a00', failure:'#1a0000', error:'#1a0000',
  flag_found:'#001a00', running:'#1a1600', default:'#111'
};

function renderTree({nodes, rootIds, width, height}){
  const svg = $('tree-svg');
  svg.setAttribute('width', width);
  svg.setAttribute('height', height);
  svg.setAttribute('viewBox', '0 0 '+width+' '+height);

  let html = '<defs><style>.tree-node-rect{cursor:pointer;transition:filter .2s}.tree-node-rect:hover{filter:brightness(1.3)}</style></defs>';

  // draw edges first
  for(const node of Object.values(nodes)){
    for(const cid of node.children){
      const child = nodes[cid];
      if(!child || node.x===undefined || child.x===undefined) continue;
      const x1=node.x+NODE_W/2, y1=node.y+NODE_H;
      const x2=child.x+NODE_W/2, y2=child.y;
      const cy=(y1+y2)/2;
      html+=`<path d="M${x1},${y1} C${x1},${cy} ${x2},${cy} ${x2},${y2}" fill="none" stroke="#333" stroke-width="1.5"/>`;
    }
  }

  // draw nodes
  for(const node of Object.values(nodes)){
    if(node.x===undefined) continue;
    const sc = STATUS_COLOR[node.status]||STATUS_COLOR.default;
    const sf = STATUS_FILL[node.status]||STATUS_FILL.default;
    const label = node.name.length>20 ? node.name.slice(0,19)+'' : node.name;
    html+=`<g onclick="selectNode('${esc(node.id)}')">`
      +`<rect class="tree-node-rect" x="${node.x}" y="${node.y}" width="${NODE_W}" height="${NODE_H}" rx="6" fill="${sf}" stroke="${sc}" stroke-width="${node.status==='running'?2:1.5}"/>`
      +`<text x="${node.x+NODE_W/2}" y="${node.y+18}" fill="${sc}" font-family="JetBrains Mono,monospace" font-size="10" text-anchor="middle" dominant-baseline="middle">${esc(label)}</text>`
      +`<text x="${node.x+NODE_W/2}" y="${node.y+32}" fill="#555" font-family="JetBrains Mono,monospace" font-size="9" text-anchor="middle" dominant-baseline="middle">${esc(node.status)}</text>`
      +`</g>`;
  }

  svg.innerHTML = html;
  // store for selectNode
  svg._nodes = nodes;
}

//  node inspector 
function selectNode(nodeId){
  const nodes = $('tree-svg')._nodes;
  if(!nodes) return;
  const node = nodes[nodeId];
  if(!node){ $('node-details-panel').innerHTML='<div class="nd-empty">Node not found.</div>'; return; }
  const sc = STATUS_COLOR[node.status]||STATUS_COLOR.default;
  let html = '<h4 style="color:'+sc+'">'+esc(node.name)+'</h4>';
  const rows = [
    ['id', node.id],
    ['status', node.status],
    ['time', (node.timestamp||'').slice(11,19)],
  ];
  if(node.error) rows.push(['error', node.error]);
  if(node.next_node) rows.push(['trigger', 'Next: ' + node.next_node]);
  
  for(const [k,v] of Object.entries(node.data||{})){
    rows.push([k, typeof v==='object'?JSON.stringify(v).slice(0,300):String(v).slice(0,300)]);
  }
  html += rows.map(([k,v])=>`<div class="nd-row"><span class="nd-key">${esc(k)}</span><span class="nd-val">${esc(v)}</span></div>`).join('');
  $('node-details-panel').innerHTML = html;
}

//  recent runs sidebar ─
async function loadRecentRuns(){
  try{
    const r = await fetch('/runs?limit=8');
    const runs = await r.json();
    const el = $('recent-runs');
    if(!runs.length){ el.innerHTML='<div style="color:var(--dim);font-size:11px">No runs yet.</div>'; return; }
    el.innerHTML = runs.map(run=>{
      const ch=run.challenge||{};
      const target=ch.url||ch.file_path||ch.name||'';
      const st=run.status||'?';
      const sc=STATUS_COLOR[st]||'#444';
      return `<div class="run-item${currentRunId===run.run_id?' active':''}" onclick="viewRun('${run.run_id}')">
        <div class="run-item-top">
          <span class="run-item-id">${run.run_id.slice(0,8)}</span>
          <span style="color:${sc};font-size:10px">${st}</span>
        </div>
        <div class="run-item-type" style="margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(target.slice(0,30))}</div>
        ${run.flag?`<div style="color:var(--green);font-size:10px;margin-top:2px">&#10003; `+esc(run.flag.slice(0,30))+'</div>':''}
      </div>`;
    }).join('');
  }catch(e){}
}
loadRecentRuns();

//  view a run ─
async function viewRun(runId){
  currentRunId = runId;
  switchTab('active');
  connectWebSocket(runId);
  loadRecentRuns();
}

//  history tab 
async function loadHistory(){
  try{
    const r = await fetch('/runs?limit=50');
    _allHistoryRows = await r.json();
    renderHistoryTable(_allHistoryRows);
  }catch(e){}
}

function renderHistoryTable(rows){
  const tbody = $('history-tbody');
  if(!rows.length){ tbody.innerHTML='<tr><td colspan="8" style="color:var(--dim);padding:16px">No runs found.</td></tr>'; return; }
  tbody.innerHTML = rows.map(run=>{
    const ch=run.challenge||{};
    const target=ch.url||ch.file_path||ch.name||'';
    const started=run.created_at?(run.created_at.slice(0,16).replace('T',' ')):'';
    const dur=fmtDur(run.created_at, run.finished_at);
    const st=run.status||'?';
    const sc=STATUS_COLOR[st]||'#444';
    return `<tr>
      <td style="color:#aaa;font-size:10px">${run.run_id.slice(0,8)}</td>
      <td>${esc(ch.type||'?')}</td>
      <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(target)}">${esc(target.slice(0,25))}</td>
      <td><span style="color:${sc}">${esc(st)}</span></td>
      <td class="flag-cell">${run.flag?esc(run.flag):''}</td>
      <td style="color:var(--dim)">${started}</td>
      <td style="color:var(--dim)">${dur}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm" onclick="viewRun('${run.run_id}')">VIEW</button>
        <button class="btn btn-sm" style="margin-left:4px" onclick="openRunModal('${run.run_id}')">DETAILS</button>
        <button class="btn btn-sm" style="margin-left:4px" onclick="rerunChallenge('${run.run_id}')">RERUN</button>
      </td>
    </tr>`;
  }).join('');
}

function filterHistory(){
  const q = $('history-search').value.toLowerCase();
  if(!q){ renderHistoryTable(_allHistoryRows); return; }
  const filtered = _allHistoryRows.filter(r=>{
    const ch=r.challenge||{};
    return (r.run_id+''+r.status+''+(r.flag||'')+(ch.url||'')+(ch.type||'')+(ch.name||'')).toLowerCase().includes(q);
  });
  renderHistoryTable(filtered);
}

async function rerunChallenge(runId){
  try{
    const r = await fetch('/runs/'+runId+'/rerun',{method:'POST'});
    if(!r.ok) throw new Error(await r.text());
    const data = await r.json();
    currentRunId = data.run_id;
    switchTab('active');
    connectWebSocket(currentRunId);
    loadRecentRuns();
  }catch(e){ alert('Rerun error: '+e.message); }
}

//  rules tab ─
async function loadRules(){
  try{
    const r = await fetch('/rules');
    _allRules = await r.json();
    renderRulesTable(_allRules);
  }catch(e){}
}

function renderRulesTable(rules){
  const tbody = $('rules-tbody');
  if(!rules.length){ tbody.innerHTML='<tr><td colspan="8" style="color:var(--dim);padding:16px">No rules found.</td></tr>'; return; }
  tbody.innerHTML = rules.map(t=>`<tr>
    <td style="color:#aaa;font-size:10px">${esc(t.id)}</td>
    <td>${esc(t.name)}</td>
    <td>${esc(t.category)}</td>
    <td>${esc(t.version)}</td>
    <td>${t.detection_paths}</td>
    <td>${t.exploitation_paths}</td>
    <td><span style="color:${t.enabled?'var(--green)':'var(--red)'}">${t.enabled?'ENABLED':'DISABLED'}</span></td>
    <td style="white-space:nowrap">
      <button class="btn btn-sm" onclick="viewRule('${esc(t.id)}')">VIEW</button>
      <button class="btn btn-sm" style="margin-left:4px" onclick="toggleRule('${esc(t.id)}', ${!t.enabled})">${t.enabled?'DISABLE':'ENABLE'}</button>
    </td>
  </tr>`).join('');
}

async function toggleRule(id, enabled){
  try{
    await fetch('/rules/'+id, {method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});
    loadRules();
  }catch(e){}
}

async function viewRule(id){
  try{
    const r = await fetch('/rules/'+id);
    const data = await r.json();
    $('rule-detail-view').classList.remove('hidden');
    $('rd-name').textContent = data.name;
    // Pretty print simplified YAML-like view
    $('rd-yaml').textContent = JSON.stringify(data, null, 2);
  }catch(e){}
}

async function reloadRules(){
  try{
    await fetch('/rules/reload', {method:'POST'});
    loadRules();
  }catch(e){}
}

function filterRules(){
  const q = $('rules-search').value.toLowerCase();
  if(!q){ renderRulesTable(_allRules); return; }
  const filtered = _allRules.filter(t=>(t.id+t.name+t.category+t.description).toLowerCase().includes(q));
  renderRulesTable(filtered);
}

//  HITL polling 
async function pollHITL(){
  try{
    const r = await fetch('/hitl/pending');
    const data = await r.json();
    const qs = data.questions||[];
    const badge = $('hitl-count');
    const hdrBadge = $('hdr-hitl-badge');
    if(qs.length){
      badge.textContent=qs.length; badge.style.display='inline';
      hdrBadge.classList.add('has-questions');
    } else {
      badge.style.display='none';
      hdrBadge.classList.remove('has-questions');
    }
    renderHITL(qs);
  }catch(e){}
}

function renderHITL(qs){
  const el = $('hitl-questions');
  if(!qs.length){ el.innerHTML='<div class="hitl-empty">No pending questions.</div>'; return; }
  el.innerHTML = qs.map(q=>`
    <div class="hitl-q" id="hitl-q-${esc(q.id)}">
      <div class="hitl-q-node">${esc(q.node_id||'unknown')}</div>
      <div class="hitl-q-text">${esc(q.question||q.text||'')}</div>
      <div class="hitl-q-input">
        <input type="text" id="hitl-ans-${esc(q.id)}" placeholder="Your answer..." onkeydown="if(event.key==='Enter')answerHITL('${esc(q.id)}')"/>
        <button class="btn btn-sm" onclick="answerHITL('${esc(q.id)}')">ANSWER</button>
      </div>
    </div>
  `).join('');
}

async function answerHITL(qid){
  const inp = $('hitl-ans-'+qid);
  if(!inp) return;
  const answer = inp.value.trim();
  try{
    const r = await fetch('/hitl/'+qid+'/answer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({answer})});
    if(!r.ok) throw new Error(await r.text());
    const el = $('hitl-q-'+qid);
    if(el) el.style.opacity='0.4';
    setTimeout(pollHITL, 500);
  }catch(e){ alert('HITL answer error: '+e.message); }
}

setInterval(pollHITL, 2000);
pollHITL();

//  crypto tools ─
function onCrTypeChange(){
  const t = $('cr-type').value;
  $('cr-params-caesar').classList.toggle('hidden', !['caesar','rot13'].includes(t));
  $('cr-params-xor').classList.toggle('hidden', t!=='xor');
  $('cr-params-rsa').classList.toggle('hidden', t!=='rsa');
}

async function cryptoSolve(){
  const ctype = $('cr-type').value;
  const text = $('cr-input').value;
  const params = {};
  if(['caesar','rot13'].includes(ctype)){ const s=$('cr-shift').value.trim(); if(s) params.shift=parseInt(s); }
  if(ctype==='xor'){ const k=$('cr-xor-key').value.trim(); if(k) params.key=k; }
  if(ctype==='rsa'){
    ['n','e','c','d','p','q'].forEach(f=>{ const v=$('cr-'+f).value.trim(); if(v) params[f]=v; });
  }
  try{
    const r = await fetch('/crypto/solve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:ctype,text,params})});
    if(!r.ok) throw new Error(await r.text());
    const data = await r.json();
    renderCryptoResults(data);
  }catch(e){ alert('Crypto solve error: '+e.message); }
}

function renderCryptoResults(data){
  const top = $('cr-flag-top');
  const list = $('cr-results-list');
  if(data.flag){
    top.style.display='block';
    top.textContent = '&#10003; FLAG FOUND: '+data.flag;
    top.innerHTML = '&#10003; FLAG FOUND: <span style="font-size:15px">'+esc(data.flag)+'</span>';
  } else {
    top.style.display='none';
  }
  const results = data.results||[];
  list.innerHTML = results.map(res=>{
    const hasFlag = !!res.flag;
    return `<div class="crypto-result${hasFlag?' has-flag':''}">
      <div class="cr-method">
        <span>${esc(res.method)}${res.note?' <span style="color:#555">('+esc(res.note)+')</span>':''}</span>
        <span style="display:flex;gap:6px;align-items:center">
          ${hasFlag?'<span class="cr-flag-badge">FLAG</span>':''}
          <button class="btn btn-sm" onclick="navigator.clipboard.writeText(${JSON.stringify(res.output)})">COPY</button>
        </span>
      </div>
      <div class="cr-output">${esc(res.output)}</div>
      ${hasFlag?'<div style="color:var(--green);font-size:11px;margin-top:4px;font-weight:700">&#10003; '+esc(res.flag)+'</div>':''}
    </div>`;
  }).join('');
}

// ── Confidence + Observations renderers ──────────────────────────────────────

function renderConfidence(conf, containerId='confidence-list'){
  const el = $(containerId);
  if(!el) return;
  const entries = Object.entries(conf||{});
  if(!entries.length){ el.innerHTML='<div class="nd-empty">No scores.</div>'; return; }
  entries.sort((a,b)=>b[1]-a[1]);
  el.innerHTML = entries.map(([id,score])=>{
    const pct = Math.round(score*100);
    const color = pct>=25?'var(--green)':pct>0?'var(--yellow)':'var(--grey)';
    const tag = pct>=10
      ? '<span class="conf-tag conf-ran">RAN</span>'
      : '<span class="conf-tag conf-skip">SKIP</span>';
    return `<div class="conf-row">
      <span class="conf-id">${esc(id)}</span>
      <div class="conf-bar-wrap"><div class="conf-bar" style="width:${pct}%;background:${color}"></div></div>
      <span class="conf-pct" style="color:${color}">${pct}%</span>
      ${tag}
    </div>`;
  }).join('');
}

function renderObservations(obs, containerId='observations-content'){
  const el = $(containerId);
  if(!el) return;
  if(!obs||!Object.keys(obs).length){ el.innerHTML='<div class="nd-empty">No data yet.</div>'; return; }
  let html = '';

  const tech = obs.tech_stack||[];
  if(tech.length)
    html += '<div class="obs-group"><div class="obs-label">TECH STACK</div><div class="chip-row">'
      +tech.map(t=>`<span class="intel-chip">${esc(t)}</span>`).join('')+'</div></div>';

  const paths = obs.found_paths||(obs.directories||[]).map(d=>d.path||'?');
  if(paths.length)
    html += '<div class="obs-group"><div class="obs-label">PATHS ('+paths.length+')</div>'
      +'<div class="obs-paths">'+paths.slice(0,20).map(p=>`<div class="obs-path">${esc(p)}</div>`).join('')+'</div></div>';

  const vc = obs.vuln_candidates||{};
  if(Object.keys(vc).length){
    html += '<div class="obs-group"><div class="obs-label">VULN CANDIDATES</div>';
    for(const [v,ev] of Object.entries(vc))
      html += `<div class="obs-vuln"><span class="obs-vuln-name">${esc(v)}</span>`
        +` <span class="obs-vuln-ev">${esc(JSON.stringify(ev).slice(0,80))}</span></div>`;
    html += '</div>';
  }

  const params = obs.params||[];
  if(params.length)
    html += '<div class="obs-group"><div class="obs-label">PARAMS</div><div class="chip-row">'
      +params.map(p=>`<span class="intel-chip">${esc(p)}</span>`).join('')+'</div></div>';

  el.innerHTML = html||'<div class="nd-empty">No observations.</div>';
}

// ── Run Detail Modal ──────────────────────────────────────────────────────────

async function openRunModal(runId){
  try{
    const r = await fetch('/runs/'+runId);
    if(!r.ok) return;
    const run = await r.json();
    $('run-detail-modal').classList.remove('hidden');
    $('modal-title').textContent = 'RUN '+runId.slice(0,8).toUpperCase();

    // ── OVERVIEW tab ──
    const ch = run.challenge||{};
    const dur = fmtDur(run.started_at||run.created_at, run.finished_at);
    const sc = STATUS_COLOR[run.status]||'#aaa';
    let ov = `<div style="padding:12px">
      <div class="nd-row"><span class="nd-key">run id</span><span class="nd-val">${esc(runId)}</span></div>
      <div class="nd-row"><span class="nd-key">status</span><span class="nd-val" style="color:${sc}">${esc(run.status)}</span></div>
      <div class="nd-row"><span class="nd-key">type</span><span class="nd-val">${esc(ch.type||'?')}</span></div>
      <div class="nd-row"><span class="nd-key">target</span><span class="nd-val">${esc(ch.url||ch.file_path||ch.name||'?')}</span></div>
      <div class="nd-row"><span class="nd-key">duration</span><span class="nd-val">${esc(dur)}</span></div>
      <div class="nd-row"><span class="nd-key">steps</span><span class="nd-val">${(run.steps||[]).length}</span></div>
      ${run.flag?`<div class="nd-row"><span class="nd-key">flag</span><span class="nd-val" style="color:var(--green);font-weight:700">${esc(run.flag)}</span></div>`:''}
      ${run.error?`<div class="nd-row"><span class="nd-key">error</span><span class="nd-val" style="color:var(--red)">${esc(run.error)}</span></div>`:''}
    </div>`;
    if(run.confidence && Object.keys(run.confidence).length){
      ov += '<div style="padding:0 12px 12px"><div class="obs-label" style="margin-bottom:6px">CONFIDENCE SCORES</div>';
      ov += _buildConfHtml(run.confidence);
      ov += '</div>';
    }
    $('modal-overview-content').innerHTML = ov;

    // ── STEPS tab ──
    $('modal-steps-content').innerHTML = _buildStepsHtml(run.steps||[]);

    // ── INTEL tab ──
    let intel = '';
    if(run.confidence && Object.keys(run.confidence).length){
      intel += '<div class="obs-group"><div class="obs-label">CONFIDENCE SCORES</div>'+_buildConfHtml(run.confidence)+'</div>';
    }
    const obs = run.observations||{};
    const tech = obs.tech_stack||[];
    if(tech.length)
      intel += '<div class="obs-group"><div class="obs-label">TECH STACK</div><div class="chip-row">'+tech.map(t=>`<span class="intel-chip">${esc(t)}</span>`).join('')+'</div></div>';
    const paths = obs.found_paths||(obs.directories||[]).map(d=>d.path||'?');
    if(paths.length)
      intel += '<div class="obs-group"><div class="obs-label">FOUND PATHS ('+paths.length+')</div>'
        +'<div class="obs-paths">'+paths.slice(0,50).map(p=>`<div class="obs-path">${esc(p)}</div>`).join('')+'</div></div>';
    const vc = obs.vuln_candidates||{};
    if(Object.keys(vc).length){
      intel += '<div class="obs-group"><div class="obs-label">VULN CANDIDATES</div>';
      for(const [v,ev] of Object.entries(vc))
        intel += `<div class="obs-vuln"><span class="obs-vuln-name">${esc(v)}</span> <span class="obs-vuln-ev">${esc(JSON.stringify(ev).slice(0,120))}</span></div>`;
      intel += '</div>';
    }
    if(obs.params?.length)
      intel += '<div class="obs-group"><div class="obs-label">PARAMS</div><div class="chip-row">'+obs.params.map(p=>`<span class="intel-chip">${esc(p)}</span>`).join('')+'</div></div>';
    $('modal-intel-content').innerHTML = intel||'<div class="nd-empty" style="padding:12px">No intel gathered.</div>';

    switchModalTab('overview');
  }catch(e){ console.error(e); }
}

function _buildConfHtml(conf){
  const entries = Object.entries(conf).sort((a,b)=>b[1]-a[1]);
  return entries.map(([id,score])=>{
    const pct = Math.round(score*100);
    const color = pct>=25?'var(--green)':pct>0?'var(--yellow)':'var(--grey)';
    return `<div class="conf-row">
      <span class="conf-id">${esc(id)}</span>
      <div class="conf-bar-wrap"><div class="conf-bar" style="width:${pct}%;background:${color}"></div></div>
      <span class="conf-pct" style="color:${color}">${pct}%</span>
      ${pct>=10?'<span class="conf-tag conf-ran">RAN</span>':'<span class="conf-tag conf-skip">SKIP</span>'}
    </div>`;
  }).join('');
}

function _buildStepsHtml(steps){
  if(!steps.length) return '<div class="nd-empty" style="padding:12px">No steps recorded.</div>';

  const yamlStarts = steps.filter(s=>s.event==='node_start'&&s.node_id&&s.node_id.includes(':'));
  const legacyStarts = steps.filter(s=>s.event==='node_start'&&s.node_id&&!s.node_id.includes(':'));
  let html = '';

  if(yamlStarts.length){
    const byTree = {};
    for(const s of yamlStarts){
      const tid = s.node_id.split(':')[0];
      (byTree[tid]||(byTree[tid]=[])).push(s);
    }
    html += '<div class="obs-label" style="padding:10px 10px 4px">YAML TREES</div>';
    for(const [tid, treeSteps] of Object.entries(byTree)){
      html += `<div class="modal-tree-group"><div class="modal-tree-name">${esc(tid)}</div>`;
      for(const s of treeSteps){
        const end = steps.find(e=>e.event==='node_end'&&e.node_id===s.node_id&&e.step>s.step);
        html += _stepRow(s, end, 'y'+s.step);
      }
      html += '</div>';
    }
  }

  if(legacyStarts.length){
    html += '<div class="obs-label" style="padding:10px 10px 4px">LEGACY TREES</div>';
    for(const s of legacyStarts){
      const end = steps.find(e=>e.event==='node_end'&&e.node_id===s.node_id&&e.step>s.step);
      html += _stepRow(s, end, 'l'+s.step);
    }
  }
  return html;
}

function _stepRow(start, end, uid){
  const status = end?.status||'running';
  const color = STATUS_COLOR[status]||'#555';
  const label = start.node_id.includes(':')
    ? start.node_id.split(':')[1]
    : (start.node_name||start.node_id);
  const data = end?.data||{};
  const hasData = Object.keys(data).length>0;
  const ts = (start.timestamp||'').slice(11,19);
  let row = `<div class="modal-step"${hasData?' onclick="toggleStepData(\'sd-'+uid+'\')" style="cursor:pointer"':''}>
    <span style="color:${color};margin-right:4px">&#9654;</span>
    <span class="modal-step-name">${esc(label)}</span>
    <span class="modal-step-status" style="color:${color}">${esc(status)}</span>
    <span class="modal-step-ts">${esc(ts)}</span>
    ${hasData?'<span class="modal-step-expand">&#x25BE;</span>':''}
  </div>`;
  if(hasData){
    row += `<div id="sd-${uid}" class="modal-step-data hidden">`;
    for(const [k,v] of Object.entries(data)){
      const val = typeof v==='object'?JSON.stringify(v,null,2).slice(0,600):String(v).slice(0,600);
      row += `<div class="nd-row"><span class="nd-key">${esc(k)}</span><span class="nd-val">${esc(val)}</span></div>`;
    }
    row += '</div>';
  }
  return row;
}

function toggleStepData(id){
  const el = $(id);
  if(el) el.classList.toggle('hidden');
}

function closeRunModal(){
  $('run-detail-modal').classList.add('hidden');
}

function switchModalTab(name){
  document.querySelectorAll('.modal-tab-panel').forEach(p=>p.classList.add('hidden'));
  document.querySelectorAll('.modal-tab').forEach(b=>b.classList.remove('active'));
  const panel = $('modal-tab-'+name);
  if(panel) panel.classList.remove('hidden');
  document.querySelectorAll('.modal-tab').forEach(b=>{
    if(b.getAttribute('onclick')&&b.getAttribute('onclick').includes("'"+name+"'"))
      b.classList.add('active');
  });
}
