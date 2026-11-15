import { $, esc, api } from './ui.js';

const TABS = ['runtime', 'alerts'];
function show(tab) {
  if (!TABS.includes(tab)) tab = 'runtime';
  for (const b of $('#tabs').children) b.setAttribute('aria-selected', b.dataset.tab === tab);
  for (const p of document.querySelectorAll('[data-panel]')) p.hidden = p.dataset.panel !== tab;
  history.replaceState(null, '', '#' + tab);
}
for (const b of $('#tabs').children) b.addEventListener('click', () => show(b.dataset.tab));

const ms = us => (us / 1000).toFixed(2) + ' ms';
const rate = x => (x === 0 ? '0%' : x < 0.001 ? (x * 100).toFixed(3) + '%' : (x * 100).toFixed(2) + '%');
const badge = ok => `<span class="badge ${ok ? 'pass' : 'fail'}">${ok ? 'In budget' : 'Over budget'}</span>`;
const vs = (el, b, a, cb, ca) => (el.innerHTML = `<div class="before"><div class="big">${b}</div><div class="cap">${cb}</div></div><div class="after"><div class="big">${a}</div><div class="cap">${ca}</div></div>`);

// ---------------------------------------------------------------- constraint 1: C++ bench results (bench/*.jsonl)
async function runtime() {
  const b = await api('/data/bench.json'), pick = (k, f) => b[k].find(r => r.pcap.includes(f));
  const [bb, ab] = [pick('before', 'busy'), pick('after', 'busy')];
  $('#rt-sub').textContent = `busy.pcap, ${bb.handshakes} real handshakes, ${b.machine}`;
  vs($('#rt-vs'), ms(bb.total_p99_us), ms(ab.total_p99_us), `Before ${badge(bb.total_p99_us < 4000)}`, `After ${badge(ab.total_p99_us < 4000)}`);
  const max = Math.max(...['before', 'after'].flatMap(k => b[k].map(r => r.total_p99_us)), 4000) * 1.1;
  $('#rt-bars').innerHTML = ['busy', 'attack'].flatMap(f => ['before', 'after'].map(k => {
    const r = pick(k, f);
    return `<div class="bar"><span>${f}.pcap · ${k}</span><span class="track"><span class="limit" style="left:${(4000 / max) * 100}%"></span>
      <span class="fill" style="width:${(r.total_p99_us / max) * 100}%;background:var(--${k === 'before' ? 'plan' : 'tuned'})"></span></span><span class="val">${ms(r.total_p99_us)}</span></div>`;
  })).join('');
  $('#rt-note').textContent = 'The budget applies to the 99th percentile. In attack.pcap every site is intercepted, and each alert waits for a full disk flush, so that capture stays over the budget.';
  const SYNC = ['Write only', 'Ordered, full flush for alerts', 'Full flush for every record'];
  $('#rt-table').innerHTML = ['before', 'after'].flatMap(k => b[k].map(r => `<tr><td class="mono">${esc(r.pcap.split('/').pop())}</td>
    <td>${k === 'before' ? 'Before' : 'After'}</td><td>${SYNC[r.log_sync] ?? '—'}</td><td class="num-c mono">${Math.round(r.logged * 100)}%</td>
    <td class="num-c mono">${ms(r.parse_us.p99)}</td><td class="num-c mono">${ms(r.decide_us.p50)}</td><td class="num-c mono">${ms(r.decide_us.p99)}</td>
    <td class="num-c mono">${ms(r.decide_us.max)}</td><td class="num-c mono"><b>${ms(r.total_p99_us)}</b></td>
    <td><span class="pill ${r.total_p99_us < 4000 ? 'clear' : 'alert'}">${r.total_p99_us < 4000 ? 'In' : 'Over'}</span></td></tr>`)).join('');
}

// ---------------------------------------------------------------- constraint 2: false alerts
const CASES = [['nominal', 'Normal traffic', false], ['stressed', 'Twice as many normal changes', false],
  ['attack', 'Interceptor', true], ['mimic', 'Interceptor that copies the server fingerprint and route', true]];
async function alerts(seed) {
  $('#rerun').disabled = true;
  $('#sim-meta').textContent = 'The server runs the tests…';
  try {
    const [s, real] = await Promise.all([api(`/api/simulate?trials=100000&seed=${seed}`), api('/api/replay?n=128')]), R = s.results;
    vs($('#fp-vs'), rate(R.plan.nominal.alert_rate), rate(R.tuned.nominal.alert_rate), 'Plan method', 'Tuned method');
    const clean = real.clients.length - real.intercepted.length;
    vs($('#real-vs'), real.compare.plan.false_alerts, real.compare.tuned.false_alerts, 'Plan method', 'Tuned method');
    $('#real-sub').textContent = `Clients with an alert, of the ${clean} clients without an interceptor. The sample is small.`;
    $('#sim-meta').textContent = `100,000 tests per case · seed ${s.seed} · ${(s.elapsed_ms / 1000).toFixed(1)} s on the server`;
    $('#fp-model').textContent = `In the simulation, 85% of sites use TLS 1.3 and 25% of sites bypass the interceptor. The last row is a known weak point of the tuned method.`;
    $('#fp-table').innerHTML = CASES.map(([k, name, att]) => `<tr><td>${name}</td><td>${att ? '<span class="pill alert">Yes</span>' : '<span class="pill none">No</span>'}</td>
      <td class="num-c mono">${rate(R.plan[k].alert_rate)}</td><td class="num-c mono"><b>${rate(R.tuned[k].alert_rate)}</b></td>
      <td class="num-c mono">${R.plan[k].mean_sites.toFixed(1)}</td><td class="num-c mono">${R.tuned[k].mean_sites.toFixed(1)}</td></tr>`).join('');
  } catch (e) { $('#sim-meta').textContent = e.message; }
  finally { $('#rerun').disabled = false; }
}
$('#rerun').addEventListener('click', () => alerts(1 + Math.floor(Math.random() * 1e6)));

show(location.hash.slice(1));
runtime();
alerts(2026);
