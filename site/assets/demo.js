import { $, esc, sgn, api, chips, hoverTip, walkChart } from './ui.js';

// ---------------------------------------------------------------- tabs (one screen each, no page scroll)
const TABS = ['live', 'lab', 'wireshark', 'log'];
function show(tab) {
  if (!TABS.includes(tab)) tab = 'live';
  for (const b of $('#tabs').children) b.setAttribute('aria-selected', b.dataset.tab === tab);
  for (const p of document.querySelectorAll('[data-panel]')) p.hidden = p.dataset.panel !== tab;
  if (tab === 'lab' && !labDone) lab('attack');
  if (tab === 'wireshark' && !wsDone) capture('attack');
  if (tab === 'log') renderLog();
  history.replaceState(null, '', '#' + tab);
}
for (const b of $('#tabs').children) b.addEventListener('click', () => show(b.dataset.tab));
const press = (group, attr, v) => { for (const b of $(group).children) if (b.dataset[attr] !== undefined) b.setAttribute('aria-pressed', b.dataset[attr] === v); };

// ---------------------------------------------------------------- live replay of busy.pcap
const TOTAL = 128, STEP = 4, TICK = 200;
let n = 0, method = 'tuned', running = false, timer = 0, R = null, prevTop = '', gen = 0, logView = null;

// Shows the state after `k` handshakes. A response that arrives after Stop, Reset or a newer request is dropped.
async function load(k = n) {
  const g = ++gen, r = await api(`/api/replay?n=${k}&method=${method}`);
  if (g !== gen) return false;
  n = k;
  R = r;
  logView = null;
  render();
  return true;
}

function render() {
  const p = R.params, other = method === 'tuned' ? 'plan' : 'tuned', c = R.compare[method];
  $('#prog-text').textContent = `${R.n} of ${R.total} handshakes`;
  $('#prog').style.width = (R.n / R.total) * 100 + '%';
  $('#k-n').textContent = R.n;
  $('#k-caught').innerHTML = `${c.caught}<small>of 2</small>`;
  $('#k-caught-foot').textContent = c.caught === 2 ? 'Both interceptors found' : 'The sensor needs 3 changed sites';
  const kfp = $('#k-fp').closest('.kpi');
  $('#k-fp').textContent = c.false_alerts;
  kfp.classList.toggle('bad', c.false_alerts > 0);
  kfp.classList.toggle('good', c.false_alerts === 0 && R.n > 0);
  $('#k-fp-foot').textContent = `Of ${R.clients.length - R.intercepted.length} clean clients. The ${other} method: ${R.compare[other].false_alerts}`;
  const t = R.timing, kt = $('#k-time').closest('.kpi');
  if (!t.n) {
    $('#k-time').textContent = '—';
    $('#k-time-foot').textContent = 'Push Run. The time updates as the handshakes come in.';
  } else {
    $('#k-time').innerHTML = `${(t.p99_us / 1000).toFixed(2)}<small>ms</small>`;
    $('#k-time-foot').textContent = `Mean ${(t.mean_us / 1000).toFixed(2)} ms. Budget 4 ms. C++ sensor on a real disk, ${t.n} handshakes.`;
  }
  kt.classList.toggle('bad', t.n > 0 && t.p99_us > t.budget_us);
  kt.classList.toggle('good', t.n > 0 && t.p99_us <= t.budget_us);
  $('#clients').innerHTML = R.clients.map(x => {
    const w = Math.min(1, Math.abs(x.score) / p.upper) * 50, col = x.score >= 0 ? 'var(--alert)' : 'var(--clear)';
    const label = { alert: 'Alert', clear: 'Clear', testing: x.sites ? `Testing, ${x.sites} sites` : 'Waiting' }[x.verdict];
    return `<div class="tile ${x.verdict}" data-testid="tile" data-ip="${esc(x.ip)}" data-verdict="${x.verdict}">
      <div class="ip">${esc(x.ip)}</div><div class="state">${label}</div>${x.intercepted ? '<span class="truth">Interceptor</span>' : ''}
      <div class="meter" title="Score ${sgn(x.score)}"><span style="left:${x.score >= 0 ? 50 : 50 - w}%;width:${w}%;background:${col}"></span></div></div>`;
  }).join('');
  const top = R.events[0] ? `${R.events[0].client}${R.events[0].site}${R.n}` : '';
  $('#feed').innerHTML = R.events.length ? R.events.map((e, i) => `<li class="${e.decision === 'alert' ? 'alert' : ''} ${i < STEP && top !== prevTop && running ? 'fresh' : ''}">
      <span class="what">${esc(e.client)} → ${esc(e.site)}</span><span>${chips(e.checks)}</span>
      <span class="meta">Step ${sgn(e.delta)}, score ${sgn(e.score)}${e.decision !== 'pending' ? ` · <b>${e.decision === 'alert' ? 'Alert' : 'Clear'}</b>` : ''}</span></li>`).join('')
    : '<li><span class="what muted">No handshakes yet</span><span class="meta">Push Run to start the replay.</span></li>';
  prevTop = top;
}

function setRunning(on, text) {
  running = on;
  $('#run').disabled = on;
  $('#stop').disabled = !on;
  $('#state-text').textContent = text;
}
async function loop() {
  if (!running) return;
  try { if (!(await load(Math.min(TOTAL, n + STEP)))) return; } catch (e) { setRunning(false, `Error: ${e.message}`); return; }
  if (n >= TOTAL) return setRunning(false, 'Finished');
  timer = setTimeout(loop, TICK);
}
$('#run').addEventListener('click', () => { if (n >= TOTAL) n = 0; setRunning(true, 'Running'); loop(); });
$('#stop').addEventListener('click', () => { clearTimeout(timer); gen++; setRunning(false, 'Stopped'); });
$('#reset').addEventListener('click', async () => { clearTimeout(timer); setRunning(false, 'Stopped'); await load(0); });
for (const b of $('#method').children) b.addEventListener('click', async () => {
  method = b.dataset.method;
  press('#method', 'method', method);
  await load();
});

// ---------------------------------------------------------------- evidence log: BLAKE2b-256, computed in this browser
// logView: every record on screen, oldest first (a copy, so "Change one record" can edit one). Verify recomputes each
// record's hash here, one at a time, and checks its link to the record before; the server then checks the same records.
const PACE = 45;  // ms between records on screen, so the eye can follow; the real time of each hash is in the Time column
const TIMES = 200;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const ZERO = '0'.repeat(64);
function logRow(r, st) {
  let j = {};
  try { j = JSON.parse(r.payload); } catch { /* an edited record may not be JSON */ }
  const kind = { notice: 'Notice', alert: 'Alert', clear: 'Clear' }[j.type] ?? '?';
  const check = !st ? '<span class="faint">—</span>' : st.run ? '<span class="muted">Computing…</span>'
    : st.ok ? '<span class="pill clear">✓ Matches</span>' : `<span class="pill alert">✗ ${st.why}</span>`;
  return `<tr data-seq="${r.seq}" class="${r.edited ? 'edited' : ''}"><td class="num-c mono muted">${r.seq}</td>
    <td><span class="pill ${j.type === 'notice' ? 'none' : j.type ?? 'none'}">${kind}</span><span class="mono"> ${esc(j.client ?? '')}${j.site ? ' · ' + esc(j.site) : ''}${j.score !== undefined ? ' · ' + sgn(j.score) : ''}</span>${r.edited ? ' <b style="color:var(--alert)">edited</b>' : ''}</td>
    <td class="mono">${r.hash.slice(0, 16)}…</td>
    <td class="mono ${st && !st.run && !st.ok ? 'forged' : ''}">${st?.computed ? st.computed.slice(0, 16) + '…' : ''}</td>
    <td class="num-c mono muted">${st?.us !== undefined ? st.us.toFixed(1) + ' µs' : ''}</td><td data-testid="check">${check}</td></tr>`;
}
function renderLog() {
  if (!R) return;
  const recs = logView ?? R.log.all;
  $('#log-sub').textContent = recs.length ? `${recs.length} records after ${R.n} handshakes, ${method} method.` : 'Run the live replay to fill the log.';
  $('#log').innerHTML = recs.map(r => logRow(r, null)).join('') || '<tr><td colspan="6" class="muted">No records yet.</td></tr>';
}
let blake;
async function verify(edit) {
  if (!R?.log.all.length) { $('#verify-result').textContent = 'Run the live replay first.'; return; }
  for (const b of [$('#verify'), $('#tamper')]) b.disabled = true;
  try {
    blake ??= (await import('./blake2b.js')).default;
    logView = R.log.all.map(r => ({ ...r }));
    if (edit) {  // an attacker hides an alert: rewrite one record, keep its old hash
      const r = logView.find(x => x.payload.includes('"alert"')) ?? logView[Math.floor(logView.length / 2)];
      r.payload = r.payload.replace(/"type":"\w+"/, '"type":"clear"').replace(/"score":-?[\d.]+/, '"score":-5');
      r.edited = true;
    }
    renderLog();
    const rows = [...$('#log').children], out = $('#verify-result');
    let last = logView[0].seq === 1 ? ZERO : logView[0].prev, bad = 0, total = 0;
    for (const [i, r] of logView.entries()) {
      rows[i].outerHTML = logRow(r, { run: true });
      const row = $('#log').children[i];
      row.scrollIntoView({ block: 'nearest' });
      out.innerHTML = `<span class="muted">Computing BLAKE2b-256 of record ${r.seq} of ${logView.length}…</span>`;
      await sleep(PACE);
      // Browsers round timers to about 0.1 ms, so one hash is timed as the mean of TIMES runs.
      const input = `${r.prev}\t${r.seq}\t${r.payload}`, t0 = performance.now();
      let computed;
      for (let k = 0; k < TIMES; k++) computed = blake.blake2bHex(input, null, 32);
      const us = ((performance.now() - t0) * 1000) / TIMES;
      total += us;
      const linked = r.prev === last, ok = linked && computed === r.hash;
      row.outerHTML = logRow(r, { computed, us, ok, why: linked ? 'Hash does not match' : 'Link broken' });
      if (!ok && !bad) bad = r.seq;
      last = r.hash;
      rows[i] = $('#log').children[i];
    }
    const v = await api('/api/verify', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ records: logView.map(({ seq, prev, payload, hash }) => ({ seq, prev, payload, hash })) }) });
    const agree = v.bad_record === bad ? 'The server agrees.' : `The server found record ${v.bad_record}.`;
    out.innerHTML = bad ? `<span class="pill alert">Record ${bad} is incorrect: its hash does not match. ${agree}</span>`
      : `<span class="pill clear">Log is correct: ${logView.length} records, BLAKE2b-256, ${(total / 1000).toFixed(2)} ms of hashing. ${agree}</span>`;
    if (bad) $(`#log tr[data-seq="${bad}"]`).scrollIntoView({ block: 'center' });
  } catch (e) { $('#verify-result').textContent = e.message; }
  finally { for (const b of [$('#verify'), $('#tamper')]) b.disabled = false; }
}
$('#verify').addEventListener('click', () => verify(false));
$('#tamper').addEventListener('click', () => verify(true));

// ---------------------------------------------------------------- lab scenarios
let labDone = false;
const DESC = {
  normal: 'The client visits the 8 sites again. No site changed.',
  onechange: 'One site has a new certificate. This is a normal change.',
  multichange: 'Four sites changed in normal ways. One site has two changes: new server software and a new route.',
  attack: 'An interceptor is between the client and all 8 sites.',
};
const walk = ev => {
  const pts = [[0, 0, '']];
  for (const e of ev) {
    if (e.result !== 'match' && e.result !== 'mismatch') continue;
    pts.push([e.sites, e.score, e.result]);
    if (e.decision !== 'pending') break;
  }
  return pts;
};
const first = r => (r.decisions[0] ? `${r.decisions[0].decision === 'alert' ? 'Alert' : 'Clear'} after ${r.decisions[0].sites} sites` : 'No decision');
async function lab(s) {
  labDone = true;
  press('#scenarios', 's', s);
  const [plan, tuned] = await Promise.all(['plan', 'tuned'].map(m => api(`/api/lab?scenario=${s}&method=${m}`)));
  $('#lab-title').textContent = { normal: 'Normal', onechange: 'One change', multichange: 'Many changes', attack: 'Attack' }[s];
  $('#lab-desc').textContent = DESC[s];
  $('#lab-verdict').textContent = `Plan: ${first(plan)} · Tuned: ${first(tuned)}`;
  walkChart($('#lab-chart'), [{ name: 'Plan method', color: 'var(--plan)', dash: '6 5', pts: walk(plan.events) },
    { name: 'Tuned method', color: 'var(--tuned)', pts: walk(tuned.events) }], tuned.params);
  const cell = x => `<span class="mono">${sgn(x.delta)}</span> <span class="mono muted">→ ${sgn(x.score)}</span>${x.decision !== 'pending' ? ` <span class="pill ${x.decision}">${x.decision === 'alert' ? 'Alert' : 'Clear'}</span>` : ''}`;
  $('#lab-rows').innerHTML = tuned.events.map((e, i) => `<tr><td>${esc(e.site)}</td>
    <td>${chips({ A: e.checks.a, B: e.checks.b_seen ? e.checks.b : null, D: e.checks.d })}</td><td class="num-c">${cell(plan.events[i])}</td><td class="num-c">${cell(e)}</td></tr>`).join('');
}
for (const b of $('#scenarios').children) b.addEventListener('click', () => lab(b.dataset.s));
hoverTip($('#lab-chart'));

// ---------------------------------------------------------------- Wireshark (tshark dissections of the lab captures)
let wsDone = false, evidence;
async function capture(c) {
  wsDone = true;
  evidence ??= await api('/data/evidence.json');
  press('#captures', 'c', c);
  const cap = evidence.captures[c];
  $('#ws-download').href = '/' + cap.file;
  $('#ws-download').textContent = `Download ${c}.pcap`;
  $('#pkts').innerHTML = cap.packets.map(p => {
    const issuer = (p.names || '').split(',')[0];
    return `<tr class="${p.no === cap.detail_frame ? 'sel' : ''}"><td class="num-c mono">${p.no}</td><td class="mono">${esc(p.src)}</td>
      <td class="num-c mono">${p.ttl}</td><td class="${issuer === 'Interceptor CA' ? 'forged' : ''}">${esc(issuer)}</td><td>${esc(p.info)}</td></tr>`;
  }).join('');
  $('#tree-title').textContent = `Frame ${cap.detail_frame}: Server Hello, Certificate`;
  $('#tree').innerHTML = cap.detail.map(l => esc(l).replace(/(Interceptor CA|Lab CA)/g, '<mark>$1</mark>')).join('\n');
}
for (const b of $('#captures').children) if (b.dataset.c) b.addEventListener('click', () => capture(b.dataset.c));

// ---------------------------------------------------------------- start
load().catch(e => ($('#state-text').textContent = `Error: ${e.message}`));
show(location.hash.slice(1));
