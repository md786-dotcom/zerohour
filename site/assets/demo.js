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
const TOTAL = 64, STEP = 2, TICK = 250;
let n = 0, method = 'tuned', running = false, timer = 0, R = null, bench = null, prevTop = '', gen = 0;

// Shows the state after `k` handshakes. A response that arrives after Stop, Reset or a newer request is dropped.
async function load(k = n) {
  const g = ++gen, r = await api(`/api/replay?n=${k}&method=${method}`);
  if (g !== gen) return false;
  n = k;
  R = r;
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
  if (bench) {
    const b = bench[method === 'tuned' ? 'after' : 'before'].find(x => x.pcap.includes('busy'));
    $('#k-time').innerHTML = `${(b.total_p99_us / 1000).toFixed(2)}<small>ms</small>`;
    $('#k-time').closest('.kpi').classList.toggle('bad', b.total_p99_us > 4000);
    $('#k-time-foot').textContent = `Budget 4 ms. ${b.total_p99_us > 4000 ? 'Over budget.' : 'In budget.'} Measured in the C++ sensor.`;
  }
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

// ---------------------------------------------------------------- evidence log (verify on the server)
function renderLog() {
  if (!R) return;
  $('#log-sub').textContent = R.log.records ? `${R.log.records} records after ${R.n} handshakes, ${method} method.` : 'Run the live replay to fill the log.';
  $('#log').innerHTML = R.log.tail.slice().reverse().map(r => {
    const j = JSON.parse(r.payload), kind = { notice: 'Notice', alert: 'Alert', clear: 'Clear' }[j.type] ?? j.type;
    return `<tr><td class="num-c mono muted">${r.seq}</td><td><span class="pill ${j.type === 'notice' ? 'none' : j.type}">${kind}</span>
      <span class="mono"> ${esc(j.client)}${j.site ? ' · ' + esc(j.site) : ''} · ${sgn(j.score)}</span></td>
      <td class="mono muted">${r.prev.slice(0, 16)}…</td><td class="mono">${r.hash.slice(0, 16)}…</td></tr>`;
  }).join('') || '<tr><td colspan="4" class="muted">No records yet.</td></tr>';
}
async function verify(edit) {
  if (!R?.log.tail.length) { $('#verify-result').textContent = 'Run the live replay first.'; return; }
  const records = R.log.tail.map(r => ({ ...r }));
  if (edit) {  // an attacker hides an alert: change one record, keep its old hash
    const r = records[Math.floor(records.length / 2)];
    r.payload = r.payload.replace(/"type":"\w+"/, '"type":"clear"').replace(/"score":-?[\d.]+/, '"score":-5');
  }
  const v = await api('/api/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ records }) });
  $('#verify-result').innerHTML = v.ok ? `<span class="pill clear">Log is correct: ${v.records} records checked</span>`
    : `<span class="pill alert">Record ${v.bad_record} was changed</span>`;
}
$('#verify').addEventListener('click', () => verify(false));
$('#tamper').addEventListener('click', () => verify(true));

// ---------------------------------------------------------------- lab scenarios
let labDone = false;
const DESC = {
  normal: 'The client visits the 8 sites again. No site changed.',
  onechange: 'One site has a new certificate. This is a normal change.',
  multichange: 'Three sites changed in normal ways: new server software, a new certificate and a new route.',
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
api('/data/bench.json').then(b => { bench = b; if (R) render(); }).catch(() => {});
load().catch(e => ($('#state-text').textContent = `Error: ${e.message}`));
show(location.hash.slice(1));
