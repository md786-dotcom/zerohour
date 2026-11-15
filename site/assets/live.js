import { $, esc, sgn, chips, hoverTip, walkChart } from './ui.js';
import { evidenceLog } from './log.js';

// Live page: step 1 learns the user's sites in a new VM, step 2 tests them again (direct or through mitmproxy), and the
// VM's evidence log. /api/live streams one JSON line per event, so each handshake shows as soon as the sensor reads it.

// ---------------------------------------------------------------- tabs (one screen each, no page scroll)
const TABS = ['learn', 'test', 'log'];
function show(tab) {
  if (!TABS.includes(tab)) tab = 'learn';
  for (const b of $('#tabs').children) b.setAttribute('aria-selected', b.dataset.tab === tab);
  for (const p of document.querySelectorAll('[data-panel]')) p.hidden = p.dataset.panel !== tab;
  if (tab === 'test' && lastTest?.params) drawChart(lastTest);  // the chart needs its final size
  if (tab === 'log') log.render();
  history.replaceState(null, '', '#' + tab);
}
for (const b of $('#tabs').children) b.addEventListener('click', () => show(b.dataset.tab));

// POSTs one step and calls onEvent for each JSON line as it arrives. An error before the stream starts is a JSON body.
async function stream(body, onEvent) {
  const r = await fetch('/api/live', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = '', done = false;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    buf += chunk.value;
    for (let i; (i = buf.indexOf('\n')) >= 0; buf = buf.slice(i + 1)) {
      const line = buf.slice(0, i);
      if (!line) continue;
      const e = JSON.parse(line);
      if (e.type === 'error') throw new Error(e.error);
      if (e.type === 'done') done = true;
      onEvent(e);
    }
  }
  if (!done) throw new Error('The connection closed before the step ended.');
}
const pcapUrl = b64 => URL.createObjectURL(new Blob([Uint8Array.from(atob(b64), c => c.charCodeAt(0))], { type: 'application/vnd.tcpdump.pcap' }));
const bar = (el, i, n) => ($(el).style.width = (n ? (i / n) * 100 : 0) + '%');

// ---------------------------------------------------------------- state
let vm = null, sites = [], params = null, ready = false, records = [], lastTest = null, running = false;
// ready: the VM has a baseline of at least min_sites learned sites, so a test can decide.
const busy = on => {
  running = on;
  $('#learn-run').disabled = on;
  $('#test-run').disabled = on || !ready;
};

// ---------------------------------------------------------------- step 1: learn
const learnRow = (s, i, st) => `<tr data-site="${esc(s.host)}" class="${st === 'now' ? 'sel' : ''}"><td class="num-c mono muted">${i + 1}</td>
  <td>${esc(s.host)}</td><td class="mono">${esc(s.ip ?? 'none')}</td>${st?.obs ? `<td>${esc(st.obs.tls)}</td><td class="mono">${esc(st.obs.ja4s)}</td>
  <td class="mono">${st.obs.key ? esc(st.obs.key) : `<span class="faint">${st.obs.tls === '1.3' ? 'hidden by TLS 1.3' : 'not seen'}</span>`}</td><td class="num-c mono">${st.obs.ttl}</td>
  <td><span class="pill clear">Learned</span></td>` : `<td colspan="4"></td>
  <td>${st === 'now' ? '<span class="muted">Visiting…</span>' : st ? `<span class="pill alert">No handshake${st.code ? ` (HTTP ${st.code})` : ''}</span>` : '<span class="faint">Waiting</span>'}</td>`}</tr>`;

$('#learn-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  if (running) return;
  const list = $('#sites').value.split(/[\s,]+/).filter(Boolean), t0 = performance.now(), state = [];
  ready = false;
  busy(true);
  $('#to-test').disabled = true;
  $('#learn-dl').hidden = true;
  $('#l-learned').textContent = '—';
  $('#l-foot').textContent = 'Starting a new VM…';
  const paint = () => ($('#learn-rows').innerHTML = sites.map((s, i) => learnRow(s, i, state[i] ?? (i === state.length ? 'now' : null))).join(''));
  try {
    await stream({ action: 'learn', sites: list, vm }, e => {
      if (e.type === 'vm') {
        vm = e.vm;
        sites = e.sites;
        records = [];
        log.reset();
        resetTest();
        $('#l-vm').innerHTML = `Running<small>${e.boot_s.toFixed(1)} s</small>`;
        $('#l-vm-foot').textContent = `Client ${e.client} behind gateway 10.9.0.1. Sensor ${e.sensor.slice(0, 7)}.`;
        $('#l-n').innerHTML = `0<small>of ${sites.length}</small>`;
        bar('#l-bar', 0, sites.length);
        $('#l-foot').textContent = `Visiting ${sites[0].host}…`;
        paint();
      } else if (e.type === 'handshake') {
        state.push(e);
        $('#l-n').innerHTML = `${e.i}<small>of ${e.total}</small>`;
        bar('#l-bar', e.i, e.total);
        $('#l-foot').textContent = e.i < e.total ? `Visiting ${sites[e.i].host}…` : 'Stopping tcpdump…';
        paint();
      } else if (e.type === 'done') {
        params = e.params;
        ready = e.learned >= params.min_sites;
        $('#l-learned').innerHTML = `${e.learned}<small>of ${e.total}</small>`;
        $('#l-foot').textContent = `Done in ${((performance.now() - t0) / 1000).toFixed(1)} s.` +
          (ready ? '' : ` Only ${e.learned} sites gave a handshake. The test needs ${params.min_sites}. Change the sites and learn again.`);
        $('#learn-dl').href = pcapUrl(e.pcap);
        $('#learn-dl').hidden = false;
        $('#to-test').disabled = !ready;
        setupTest();
      }
    });
  } catch (err) {
    $('#l-foot').textContent = `Error: ${err.message}`;
    if (!ready) { vm = null; $('#l-vm').textContent = '—'; $('#l-vm-foot').textContent = 'No VM.'; }  // the server stops a VM whose learn failed
  } finally { busy(false); }
});
$('#to-test').addEventListener('click', () => show('test'));

// ---------------------------------------------------------------- step 2: test
// Scenarios, as in the lab: each one says what is different on the second visit for each site (by position in the list).
//   route: replies come through 3 more routers (TTL)   tls: the server answers with other TLS settings   mitm: mitmproxy
const SCEN = {
  direct: {
    normal: { label: 'Normal', text: 'The client visits the sites again. No site changed.', plan: () => ({}) },
    one: { label: 'One change', text: 'One site has a new route: its replies come through 3 more routers. This is a normal change.',
      plan: h => ({ [h[1]]: 'route' }) },
    many: { label: 'Many changes', text: 'Up to four sites changed in normal ways: new routes and new server settings (TLS). One site has both changes.',
      plan: h => Object.fromEntries(['route', 'tls', 'route', 'both'].slice(0, h.length).map((k, i) => [h[i], k])) },
  },
  mitm: {
    attack: { label: 'Attack', text: 'Every site goes through mitmproxy: an interceptor is between the client and all sites.',
      plan: h => Object.fromEntries(h.map(x => [x, 'mitm'])) },
  },
};
const CHANGE = { none: ['none', 'same as step 1'], route: ['none', 'new route'], tls: ['none', 'new TLS settings'],
  both: ['none', 'new route + TLS'], mitm: ['alert', 'mitmproxy'] };
let path = 'direct', scen = 'normal';
const plan = () => SCEN[path][scen].plan(sites.map(s => s.host));
function setScen() {
  if (!SCEN[path][scen]) scen = Object.keys(SCEN[path])[0];  // mitmproxy has only Attack
  $('#scen').innerHTML = Object.entries(SCEN[path]).map(([k, v]) =>
    `<button type="button" aria-pressed="${k === scen}" data-scen="${k}">${v.label}</button>`).join('');
  for (const b of $('#scen').children) b.addEventListener('click', () => { scen = b.dataset.scen; setScen(); });
  $('#t-head').textContent = `The client visits the same sites again. ${SCEN[path][scen].text}`;
  if (!running && sites.length) paintPlan();
}
for (const b of $('#path').children) b.addEventListener('click', () => {
  path = b.dataset.path;
  for (const x of $('#path').children) x.setAttribute('aria-pressed', x === b);
  setScen();
});
const changeCell = k => `<span class="pill ${CHANGE[k ?? 'none'][0]}">${CHANGE[k ?? 'none'][1]}</span>`;
function paintPlan() {  // before a run: what each site will get
  const p = plan();
  $('#test-rows').innerHTML = sites.map((s, i) => `<tr data-site="${esc(s.host)}"><td class="num-c mono muted">${i + 1}</td><td>${esc(s.host)}</td>
    <td>${changeCell(p[s.host])}</td><td></td><td></td><td></td></tr>`).join('');
}

// The gauge, its labels and the help text come from the engine's parameters (thresholds and the per-site cap).
const span = () => params.upper + 1.5;  // the gauge runs from -span to +span
const pos = v => (Math.max(-span(), Math.min(span(), v)) / span()) * 50 + 50;
function setupTest() {
  const zone = 100 - pos(params.upper);
  for (const z of document.querySelectorAll('.gauge .zone')) z.style.width = zone + '%';
  $('.gauge .lo').style.left = $('.gauge .hi').style.right = zone + '%';
  $('.gauge .lo').textContent = `${sgn(params.lower)} clear`;
  $('.gauge .hi').textContent = `${sgn(params.upper)} alert`;
  $('#t-score-foot').textContent = `Each handshake moves the score. A changed site adds up to ${sgn(params.site_cap)}. A same site subtracts.`;
  $('#t-n').innerHTML = `0<small>of ${sites.length}</small>`;
  bar('#t-bar', 0, sites.length);
  $('#t-foot').textContent = ready ? 'Choose the path and a scenario, then push Run test.' : 'The baseline has too few sites. Do step 1 again.';
  setScore(0);
  setScen();
}
function resetTest() {  // a new run or a new VM: nothing from the last run stays on screen
  lastTest = null;
  $('#test-rows').innerHTML = '<tr><td colspan="6" class="muted">No test yet.</td></tr>';
  $('#t-chart').innerHTML = '';
  $('#test-dl').hidden = true;
  $('#t-score').textContent = '0.00';
  $('#t-score').style.color = '';
  $('#t-decision').textContent = '—';
  $('#t-dec-foot').innerHTML = '&nbsp;';
  $('#t-time').textContent = '—';
  $('#t-time-foot').textContent = 'Engine time per handshake.';
  for (const id of ['#t-score-card', '#t-dec-card', '#t-time-card']) $(id).classList.remove('bad', 'good');
}
setScen();

function setScore(score) {
  $('#t-score').textContent = sgn(score);
  $('#t-score').style.color = score >= params.upper ? 'var(--alert)' : score <= params.lower ? 'var(--clear)' : '';
  $('#t-needle').style.left = pos(score) + '%';
}
// The verdict to show: an alert wins over a clear, else the first verdict, else none.
const verdictOf = t => t.events.find(e => e.decision === 'alert') ?? t.events.find(e => e.known && e.decision !== 'pending');
// One line: the TRW test that gave the verdict (a verdict ends a test; the next site starts a new one), else the open test.
function drawChart(t) {
  const v = verdictOf(t), tests = [[]];
  for (const e of t.events) {
    if (!e.known) continue;
    tests.at(-1).push(e);
    if (e.decision !== 'pending') tests.push([]);
  }
  const shown = v ? tests.find(x => x.includes(v)) : tests.at(-1);
  const pts = [[0, 0, ''], ...shown.map(e => [e.sites, e.score, e.checks.A || e.checks.B || e.checks.D ? 'mismatch' : 'match'])];
  walkChart($('#t-chart'), [{ name: 'Tuned method', color: 'var(--tuned)', pts }], { ...t.params, xmax: Math.max(6, sites.length) });
  $('#t-chart-sub').textContent = tests.filter(x => x.length).length > 1
    ? 'The test that gave the verdict. Filled dot: the site changed. Open dot: the site is the same.'
    : 'Filled dot: the site changed. Open dot: the site is the same.';
}
const stepCell = e => !e.obs ? '<span class="muted">no handshake</span>' : !e.known ? '<span class="muted">not learned</span>' : `<span class="mono">${sgn(e.delta)}</span>`;
const scoreCell = e => e.known ? `<span class="mono">${sgn(e.score)}</span>${e.decision !== 'pending' ? ` <span class="pill ${e.decision}">${e.decision === 'alert' ? 'Alert' : 'Clear'}</span>` : ''}` : '';

$('#test-run').addEventListener('click', async () => {
  if (running || !ready) return;
  const changes = plan(), t0 = performance.now();
  busy(true);
  resetTest();
  $('#t-decision').textContent = 'Testing';
  $('#t-foot').textContent = 'Connecting to the VM…';
  const t = (lastTest = { events: [], params, changes });
  const paint = () => {
    $('#test-rows').innerHTML = sites.map((s, i) => {
      const e = t.events[i], now = i === t.events.length;
      return `<tr data-site="${esc(s.host)}" class="${now ? 'sel' : ''}"><td class="num-c mono muted">${i + 1}</td><td>${esc(s.host)}</td>
        <td>${changeCell(t.changes[s.host])}</td>
        <td>${e?.known ? chips(e.checks) : ''}</td><td class="num-c">${e ? stepCell(e) : now ? '<span class="muted">Visiting…</span>' : ''}</td>
        <td class="num-c">${e ? scoreCell(e) : ''}</td></tr>`;
    }).join('');
  };
  try {
    await stream({ action: 'test', vm, changes }, e => {
      if (e.type === 'start') {
        t.params = e.params;
        t.changes = e.changes;
        setScore(0);
        $('#t-n').innerHTML = `0<small>of ${e.total}</small>`;
        bar('#t-bar', 0, e.total);
        const extra = Object.keys(e.changes).filter(h => e.changes[h] !== 'none' && !changes[h]);
        $('#t-foot').textContent = `Test ${e.run}. Visiting ${sites[0].host}…`;
        if (extra.length) $('#t-dec-foot').textContent = `${extra.join(', ')} also changed: same IPv4 address as a changed site.`;
        paint();
        drawChart(t);
      } else if (e.type === 'handshake') {
        t.events.push(e);
        // The big score shows the test that gave the verdict (an alert wins); with no verdict yet, the current score.
        const v = verdictOf(t);
        setScore(v ? v.score : e.known ? e.score : t.events.findLast(x => x.known)?.score ?? 0);
        if (v) {
          const all = t.events.filter(x => x.known && x.decision !== 'pending');
          $('#t-decision').textContent = v.decision === 'alert' ? 'Alert' : 'Clear';
          $('#t-dec-foot').textContent = all.map(x => `${x.decision === 'alert' ? 'Alert' : 'Clear'} after ${x.sites} sites (handshake ${x.i})`).join(', then ') + '.';
          for (const id of ['#t-dec-card', '#t-score-card']) {
            $(id).classList.toggle('bad', v.decision === 'alert');
            $(id).classList.toggle('good', v.decision === 'clear');
          }
          if (e.known && e !== v) $('#t-score-foot').textContent = `A verdict ends a test. The next sites start a new test: score now ${sgn(e.score)}.`;
        }
        $('#t-n').innerHTML = `${e.i}<small>of ${e.total}</small>`;
        bar('#t-bar', e.i, e.total);
        $('#t-foot').textContent = e.i < e.total ? `Visiting ${sites[e.i].host}…` : 'Stopping tcpdump…';
        paint();
        drawChart(t);
      } else if (e.type === 'done') {
        if (!e.decisions.length) {
          $('#t-decision').textContent = 'No decision';
          $('#t-dec-foot').textContent = `Score ${sgn(t.events.findLast(x => x.known)?.score ?? 0)}. More sites are necessary.`;
        }
        const m = e.timing;
        if (m.n) {
          $('#t-time').innerHTML = `${(m.p99_us / 1000).toFixed(2)}<small>ms</small>`;
          $('#t-time-foot').textContent = `Mean ${(m.mean_us / 1000).toFixed(2)} ms, ${m.n} handshakes. Check, score and log record in memory; not the packet parse.`;
        }
        $('#t-foot').textContent = `Done in ${((performance.now() - t0) / 1000).toFixed(1)} s.`;
        $('#test-dl').href = pcapUrl(e.pcap);
        $('#test-dl').download = `test-${e.run}.pcap`;
        $('#test-dl').hidden = false;
        records = e.log;
        log.reset();
      }
    });
  } catch (err) {
    $('#t-foot').textContent = `Error: ${err.message}`;
    if (/Learn/.test(err.message)) { vm = null; ready = false; $('#to-test').disabled = true; }
  } finally { busy(false); }
});
hoverTip($('#t-chart'));

// ---------------------------------------------------------------- evidence log of this VM (assets/log.js)
const log = evidenceLog({ records: () => records, empty: 'Run a test first.',
  sub: k => (k ? `${k} records from the tests in this VM.` : 'Run a test to fill the log.') });

// The VM stops by itself after 15 minutes; stop it now when the page really closes (not on a back/forward cache visit).
addEventListener('pagehide', e => {
  if (vm && !e.persisted) navigator.sendBeacon('/api/live', new Blob([JSON.stringify({ action: 'stop', vm })], { type: 'application/json' }));
});
show(location.hash.slice(1));
