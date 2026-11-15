import { $, esc, sgn, us, api, chips, hoverTip, walkChart } from './ui.js';

const fmtRate = x => (x === 0 ? '0%' : x < 0.0001 ? (x * 100).toFixed(4) + '%' : x < 0.01 ? (x * 100).toFixed(3) + '%' : (x * 100).toFixed(2) + '%');
const bar = (label, v, frac, color, limit) => `<div class="bar"><span class="t2">${label}</span>
  <span class="track">${limit ? '<span class="limit" style="right:0"></span>' : ''}<span class="fill" style="width:${Math.max(0.4, Math.min(100, frac * 100))}%;background:${color}"></span></span>
  <span class="val">${v}</span></div>`;

// ---------------------------------------------------------------- runtime (C++ bench, committed results)
async function runtime() {
  const b = await api('/data/bench.json');
  $('#machine').textContent = `an ${b.machine}`;
  const worst = r => r.parse_us.p99 + r.decide_us.max, att = k => b[k].find(r => r.pcap.includes('attack'));
  const [bf, af] = [att('before'), att('after')];
  $('#rt-before').textContent = us(worst(bf));
  $('#rt-after').textContent = us(worst(af));
  $('#rt-note').innerHTML = `Both versions are inside the 4 ms budget. After, the worst case uses <b>${((worst(af) / 4000) * 100).toFixed(0)}%</b> of it instead of ${((worst(bf) / 4000) * 100).toFixed(0)}%, and the typical decision on an alerting site drops from ${us(bf.decide_us.p50)} to <b>${us(af.decide_us.p50)}</b>.`;
  const rows = [['Worst case', worst], ['Decide, max', r => r.decide_us.max], ['Total, p99', r => r.total_p99_us]];
  $('#rt-bars').innerHTML = rows.flatMap(([l, f]) => [
    bar(`${l} · before`, us(f(bf)), f(bf) / 4000, 'var(--plan)', true),
    bar(`${l} · after`, us(f(af)), f(af) / 4000, 'var(--tuned)', true)]).join('');
  $('#rt-table').innerHTML = ['before', 'after'].flatMap(k => b[k].map(r => `<tr><td class="mono">${esc(r.pcap.split('/').pop())}</td>
    <td>${k === 'before' ? 'Before (plan)' : 'After (tuned)'}</td><td class="num mono">${r.parse_us.p99.toFixed(1)}</td><td class="num mono">${r.decide_us.p50.toFixed(2)}</td>
    <td class="num mono">${r.decide_us.p99.toFixed(1)}</td><td class="num mono">${r.decide_us.max.toFixed(0)}</td><td class="num mono"><b>${worst(r).toFixed(0)}</b></td></tr>`)).join('');
  api('/api/live').then(L => ($('#rt-live').textContent = `${L.stats.latency_us.p99.toFixed(1)} µs`)).catch(() => {});
}

// ---------------------------------------------------------------- false alerts (live Monte Carlo)
const CASES = [['nominal', 'Normal traffic', 'benign'], ['stressed', 'Twice the normal change rate', 'benign'],
  ['attack', 'Interceptor on every site', 'attack'], ['mimic', 'Interceptor copying JA4S and TTL', 'attack']];
const logFrac = x => (Math.log10(Math.max(x, 1e-5)) + 5) / 5;  // 0.001% .. 100%

async function falseAlerts(seed) {
  $('#rerun').disabled = true;
  $('#sim-meta').textContent = 'Running 100,000 tests per case on the server…';
  try {
    const s = await api(`/api/simulate?trials=100000&seed=${seed}`), R = s.results;
    const pb = R.plan.nominal.alert_rate, pa = R.tuned.nominal.alert_rate;
    $('#fp-before').textContent = fmtRate(pb);
    $('#fp-after').textContent = fmtRate(pa);
    $('#fp-before-cap').textContent = `false alerts before · ${R.plan.nominal.alerts.toLocaleString()} of ${s.trials.toLocaleString()} tests`;
    $('#fp-after-cap').textContent = `false alerts after · ${R.tuned.nominal.alerts.toLocaleString()} of ${s.trials.toLocaleString()} tests`;
    const ratio = pa ? Math.round(pb / pa).toLocaleString() + '×' : `more than ${Math.round(pb / R.tuned.nominal.alert_ci[1]).toLocaleString()}×`;
    $('#fp-note').innerHTML = `<b>${ratio} fewer false alerts</b> on normal traffic, and ${fmtRate(R.plan.stressed.alert_rate)} → ${fmtRate(R.tuned.stressed.alert_rate)} when sites change twice as often.
      Detection of an interceptor stays at ${fmtRate(R.tuned.attack.alert_rate)}, after ${R.tuned.attack.mean_sites.toFixed(2)} sites on average instead of ${R.plan.attack.mean_sites.toFixed(2)}.
      <br><b>Trade-off:</b> an interceptor that copies every server's JA4S and hop count fails only check B. The tuned method treats a single failed check as normal, so it catches this case ${fmtRate(R.tuned.mimic.alert_rate)} of the time, against ${fmtRate(R.plan.mimic.alert_rate)} before.`;
    $('#sim-meta').textContent = `${s.trials.toLocaleString()} tests per case · seed ${s.seed} · ${(s.elapsed_ms / 1000).toFixed(2)} s in the Vercel function`;
    $('#fp-bars').innerHTML = CASES.flatMap(([k, name]) => [
      bar(`${name} · before`, fmtRate(R.plan[k].alert_rate), logFrac(R.plan[k].alert_rate), 'var(--plan)'),
      bar(`${name} · after`, fmtRate(R.tuned[k].alert_rate), logFrac(R.tuned[k].alert_rate), 'var(--tuned)')]).join('');
    const ci = r => `<span class="muted">${fmtRate(r.alert_ci[0])}–${fmtRate(r.alert_ci[1])}</span>`;
    $('#fp-table').innerHTML = CASES.map(([k, name, kind]) => `<tr><td>${name}</td><td>${kind === 'benign' ? '<span class="tag">no interceptor</span>' : '<span class="tag tp">interceptor</span>'}</td>
      <td class="num mono">${fmtRate(R.plan[k].alert_rate)} ${ci(R.plan[k])}</td><td class="num mono"><b>${fmtRate(R.tuned[k].alert_rate)}</b> ${ci(R.tuned[k])}</td>
      <td class="num mono">${R.plan[k].mean_sites.toFixed(2)}</td><td class="num mono">${R.tuned[k].mean_sites.toFixed(2)}</td></tr>`).join('');
    const m = s.models;
    $('#fp-model').innerHTML = `<b>Assumed change rates per site on a revisit.</b> Normal traffic: JA4S ${fmtRate(m.nominal.a)}, certificate ${fmtRate(m.nominal.b)}, route ${fmtRate(m.nominal.d)},
      plus ${fmtRate(m.nominal.migrate)} provider migrations that change all three at once. ${fmtRate(m.nominal.tls13)} of sites use TLS 1.3, which hides the certificate.
      The interceptor fails JA4S ${fmtRate(m.attack.a)}, certificate ${fmtRate(m.attack.b)}, route ${fmtRate(m.attack.d)} of the time.
      These numbers are assumptions. Run <code>zerohour calibrate</code> on real captures to replace them.`;
    $('#cases').innerHTML = s.cases.map(c => `<tr><td>${esc(c.name)} ${c.kind === 'attack' ? '<span class="tag tp">interceptor</span>' : ''}</td>
      <td>${chips({ A: c.checks.a, B: c.checks.b_seen ? c.checks.b : null, D: c.checks.d })}</td>
      <td class="num mono">${sgn(c.plan)}</td><td class="num mono"><b>${sgn(c.tuned)}</b></td></tr>`).join('');
  } catch (e) { $('#sim-meta').textContent = e.message; }
  finally { $('#rerun').disabled = false; }
}
$('#rerun').addEventListener('click', () => falseAlerts(1 + Math.floor(Math.random() * 1e6)));

// ---------------------------------------------------------------- lab walks
const walk = ev => {
  const pts = [[0, 0, '']];
  for (const e of ev) {
    if (e.result !== 'match' && e.result !== 'mismatch') continue;
    pts.push([e.sites, e.score, e.result]);
    if (e.decision !== 'pending') break;
  }
  return pts;
};
const first = r => (r.decisions[0] ? `${r.decisions[0].decision === 'alert' ? 'alert' : 'clear'} after ${r.decisions[0].sites} sites` : 'no decision');
async function walks() {
  for (const [s, id] of [['multichange', 'multi'], ['attack', 'attack']]) {
    const [plan, tuned] = await Promise.all(['plan', 'tuned'].map(m => api(`/api/lab?scenario=${s}&method=${m}`)));
    $(`#w-${id}`).textContent = `Before: ${first(plan)} · After: ${first(tuned)}`;
    walkChart($(`#c-${id}`), [{ name: 'Before', color: 'var(--plan)', dash: '6 5', pts: walk(plan.events) },
      { name: 'After', color: 'var(--tuned)', pts: walk(tuned.events) }], tuned.params);
    hoverTip($(`#c-${id}`));
  }
}

runtime();
falseAlerts(2026);
walks();
