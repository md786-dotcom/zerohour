import { $, esc, sgn, us, clock, api, chips, hoverTip, walkChart } from './ui.js';

let method = 'tuned', state = null, seen = new Set(), timer = 0;

// ---------------------------------------------------------------- live console
const meter = (score, upper) => {
  const w = Math.min(1, Math.abs(score) / upper) * 50;
  const col = score >= 0 ? 'var(--critical)' : 'var(--good)';
  return `<span class="meter" aria-hidden="true"><span style="left:${score >= 0 ? 50 : 50 - w}%;width:${w}%;background:${col}"></span></span>`;
};
const verdict = d => (d === 'alert' ? '<span class="st alert">Alert</span>' : d === 'clear' ? '<span class="st clear">Clear</span>' : '<span class="st pending">Testing</span>');

function render(L) {
  const p = L.params, s = L.stats, c = L.compare[L.method], other = L.compare[L.method === 'tuned' ? 'plan' : 'tuned'];
  $('#k-rate').textContent = s.handshakes_per_min;
  $('#k-rate-sub').textContent = `${s.handshakes_window.toLocaleString()} in the last 10 minutes · ${s.sites} servers`;
  $('#k-clients').textContent = s.clients;
  $('#k-clients-sub').textContent = `${L.clients.filter(x => x.sites > 0).length} with a test running`;
  $('#k-alerts').textContent = c.alerts;
  $('#k-alerts-sub').innerHTML = `${c.true_alerts} confirmed · <b style="color:${c.false_alerts ? 'var(--warn)' : 'inherit'}">${c.false_alerts} false</b> · the ${L.method === 'tuned' ? 'plan' : 'tuned'} method: ${other.false_alerts} false`;
  $('#k-lat').innerHTML = `${s.latency_us.p99.toFixed(1)}<small>µs</small>`;
  $('#k-lat-sub').textContent = `max ${us(s.latency_us.max)} · budget 4 ms · ${s.latency_us.n.toLocaleString()} decisions`;
  $('#k-lat-bar').style.width = Math.min(100, (s.latency_us.p99 / s.budget_us) * 100) + '%';
  $('#next-attack').textContent = L.clients.some(x => x.intercepted_now) ? 'An interception is running now.' : `Next interception in ${L.next_attack_in_s} s.`;
  $('#clients-sub').textContent = `Score of the running test. Alert at ${sgn(p.upper)}, clear at ${sgn(p.lower)}.`;

  const rows = [...L.clients].sort((a, b) => b.intercepted_now - a.intercepted_now || b.score - a.score);
  $('#clients').innerHTML = rows.map(x => `<tr>
    <td><b style="font-weight:600">${esc(x.name)}</b> <span class="muted mono">${esc(x.ip)}</span>${x.intercepted_now ? ' <span class="tag tp" title="Simulation ground truth">interceptor active</span>' : ''}</td>
    <td class="t2">${esc(x.browser)}</td>
    <td>${meter(x.score, p.upper)} <span class="mono t2">${sgn(x.score)}</span></td>
    <td class="num">${x.sites}</td>
    <td>${x.last_decision ? `${verdict(x.last_decision.decision)} <span class="muted">${clock(x.last_decision.t)}</span>` : verdict('pending')}</td></tr>`).join('');

  $('#alerts').innerHTML = L.alerts.length ? L.alerts.map(a => `<li class="${a.truth ? '' : 'fp'}">
      <div class="row1"><span class="st alert">${esc(a.host)}</span><span class="mono muted">${esc(a.client)}</span>
      <span class="tag ${a.truth ? 'tp' : 'fp'}">${a.truth ? 'confirmed interceptor' : 'false alert'}</span></div>
      <div class="row2">${clock(a.t)} · after ${a.sites} sites · score ${sgn(a.score)}</div></li>`).join('')
    : '<li class="empty"><b>No alerts in the last 10 minutes</b>The next interception starts in ' + L.next_attack_in_s + ' s.</li>';

  const fresh = new Set();
  $('#events').innerHTML = L.events.slice(0, 60).map(e => {
    const k = `${e.ts}|${e.client}`;
    fresh.add(k);
    const isNew = seen.size && !seen.has(k);
    return `<tr class="${isNew ? 'fresh' : ''}"><td class="mono muted">${clock(e.ts)}</td><td>${esc(e.host)}</td><td>${esc(e.site)}</td><td class="t2">${esc(e.tls)}</td>
      <td class="mono muted">${esc(e.ja4s)}</td><td>${chips(e.checks)}</td>
      <td class="num mono">${e.result === 'repeat' ? '<span class="muted">repeat</span>' : sgn(e.delta)}</td><td class="num mono">${sgn(e.score)}</td>
      <td>${e.decision === 'pending' ? '' : verdict(e.decision)}</td></tr>`;
  }).join('');
  seen = fresh;

  if (!tampered) {
    $('#log-sub').textContent = `${L.log.records.toLocaleString()} records in this window · head ${L.log.head?.slice(0, 16) ?? '—'}…`;
    $('#log').innerHTML = [...L.log.tail].reverse().slice(0, 10).map(r => {
      const j = JSON.parse(r.payload);
      return `<tr><td class="num mono muted">${r.seq}</td><td>${j.type === 'notice' ? '<span class="st warn">Notice</span>' : verdict(j.type)} <span class="t2">${esc(j.client)}${j.site ? ' · ' + esc(j.site) : ''} · ${sgn(j.score)}</span></td>
        <td class="mono muted">${r.prev.slice(0, 12)}…</td><td class="mono">${r.hash.slice(0, 12)}…</td></tr>`;
    }).join('');
  }
}

async function tick() {
  clearTimeout(timer);
  try {
    state = await api(`/api/live?method=${method}`);
    render(state);
    $('#live').classList.remove('paused');
    $('#live-text').textContent = `Live · simulated campus network · ${clock(state.now)}`;
  } catch (e) {
    $('#live').classList.add('paused');
    $('#live-text').textContent = `Offline: ${e.message}`;
  }
  if (document.visibilityState === 'visible') timer = setTimeout(tick, 2000);
}
document.addEventListener('visibilitychange', () => document.visibilityState === 'visible' && tick());

for (const b of $('#method').querySelectorAll('button')) b.addEventListener('click', () => {
  method = b.dataset.method;
  for (const x of $('#method').querySelectorAll('button')) x.setAttribute('aria-pressed', x === b);
  seen = new Set();
  tick();
});

// ---------------------------------------------------------------- evidence log: verify / tamper on the server
let tampered = false;
async function verify(edit) {
  if (!state) return;
  const records = state.log.tail.map(r => ({ ...r }));
  const out = $('#verify-result');
  if (edit) {  // an attacker hides the alert trail: rewrite one record's payload, keep its hash
    const r = records[Math.floor(records.length / 2)];
    r.payload = r.payload.replace(/"type":"\w+"/, '"type":"clear"').replace(/"score":-?[\d.]+/, '"score":-5');
    tampered = true;
    setTimeout(() => (tampered = false), 8000);
  }
  for (const b of [$('#verify'), $('#tamper')]) b.disabled = true;
  try {
    const v = await api('/api/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ records }) });
    out.innerHTML = v.ok ? `<span class="st clear">Chain intact</span> ${v.records} records recomputed on the server`
      : `<span class="st alert">Chain broken at record ${v.bad_record}</span> ${esc(v.reason)}: the edited record no longer matches its hash`;
  } catch (e) { out.textContent = e.message; }
  finally { for (const b of [$('#verify'), $('#tamper')]) b.disabled = false; }
}
$('#verify').addEventListener('click', () => verify(false));
$('#tamper').addEventListener('click', () => verify(true));

// ---------------------------------------------------------------- lab replay
const DESC = {
  normal: 'The client visits the same 8 sites again. Nothing changed.',
  onechange: 'site3 renewed its certificate (check B). A normal event.',
  multichange: 'Three normal changes: site2 new server software (A), site3 renewed certificate (B), site6 new route (D).',
  attack: 'An interceptor with its own root CA sits between the client and every site.',
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
const first = r => r.decisions[0] ? `${r.decisions[0].decision === 'alert' ? 'Alert' : 'Clear'} after ${r.decisions[0].sites} sites` : 'No decision';
async function lab(s) {
  for (const b of $('#scenarios').querySelectorAll('button')) b.setAttribute('aria-selected', b.dataset.s === s);
  const [plan, tuned] = await Promise.all(['plan', 'tuned'].map(m => api(`/api/lab?scenario=${s}&method=${m}`)));
  $('#lab-title').textContent = { normal: 'Normal', onechange: 'One change', multichange: 'Many changes', attack: 'Attack' }[s];
  $('#lab-verdict').textContent = `Plan: ${first(plan)} · Tuned: ${first(tuned)}`;
  $('#lab-desc').textContent = DESC[s];
  walkChart($('#lab-chart'), [
    { name: 'Plan method', color: 'var(--plan)', dash: '6 5', pts: walk(plan.events) },
    { name: 'Tuned method', color: 'var(--tuned)', pts: walk(tuned.events) },
  ], tuned.params);
  $('#lab-rows').innerHTML = tuned.events.map((e, i) => {
    const q = plan.events[i], cell = x => `<span class="mono">${sgn(x.delta)}</span> <span class="muted mono">→ ${sgn(x.score)}</span>${x.decision !== 'pending' ? ' ' + verdict(x.decision) : ''}`;
    return `<tr><td>${esc(e.site)}</td><td>${chips({ A: e.checks.a, B: e.checks.b_seen ? e.checks.b : null, D: e.checks.d })}</td><td class="num">${cell(q)}</td><td class="num">${cell(e)}</td></tr>`;
  }).join('');
}
for (const b of $('#scenarios').querySelectorAll('button')) b.addEventListener('click', () => lab(b.dataset.s));
hoverTip($('#lab-chart'));

// ---------------------------------------------------------------- packet evidence (tshark)
let evidence;
async function capture(c) {
  evidence ??= await api('/data/evidence.json');
  for (const b of $('#captures').querySelectorAll('button')) b.setAttribute('aria-selected', b.dataset.c === c);
  const cap = evidence.captures[c];
  $('#ev-download').href = '/' + cap.file;
  $('#ev-download').textContent = `Download ${c}.pcap`;
  $('#ev-sub').firstChild.textContent = `The same lab captures, dissected by ${evidence.tshark.replace(/ \(v.*/, '')}. `;
  $('#pkts').innerHTML = cap.packets.map(p => {
    const [issuer, subject] = (p.names || '').split(',');
    return `<tr aria-selected="${p.no === cap.detail_frame}"><td class="num mono">${p.no}</td><td class="mono">${esc(p.src)}</td><td class="mono">${esc(p.dst)}</td>
      <td class="num mono">${p.ttl}</td><td>${esc(p.info)}</td>
      <td class="${issuer === 'Interceptor CA' ? 'cert-int' : ''}">${issuer ? `${esc(issuer)} → ${esc(subject)}` : ''}</td></tr>`;
  }).join('');
  $('#tree-title').textContent = `Frame ${cap.detail_frame}: Server Hello, Certificate`;
  $('#tree').innerHTML = cap.detail.map(l => esc(l).replace(/(Interceptor CA|Lab CA)/g, '<mark>$1</mark>')).join('\n');
}
for (const b of $('#captures').querySelectorAll('button')) b.addEventListener('click', () => capture(b.dataset.c));

tick();
lab('attack');
capture('attack');
