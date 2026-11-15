import { $, esc, sgn, api, hoverTip } from './ui.js';

const TABS = ['measure', 'weigh', 'cap', 'result'];
function show(tab) {
  if (!TABS.includes(tab)) tab = 'measure';
  for (const b of $('#tabs').children) b.setAttribute('aria-selected', b.dataset.tab === tab);
  for (const p of document.querySelectorAll('[data-panel]')) p.hidden = p.dataset.panel !== tab;
  history.replaceState(null, '', '#' + tab);
  if (T) draw();  // charts need their final size
}
for (const b of $('#tabs').children) b.addEventListener('click', () => show(b.dataset.tab));

const pct = (x, d = 2) => (x * 100).toFixed(x > 0 && x < 0.001 ? 3 : d) + '%';
const NAME = { a: 'A · server fingerprint', b: 'B · certificate key', d: 'D · network path' };
let T = null, real = null;

function vs(el, before, after, capB, capA) {
  el.innerHTML = `<div class="before"><div class="big">${before}</div><div class="cap">${capB}</div></div>
    <div class="after"><div class="big">${after}</div><div class="cap">${capA}</div></div>`;
}

// Small line chart, one series, with the chosen point marked.
function line(svg, pts, fmt, chosen) {
  const W = svg.clientWidth || 500, H = svg.clientHeight || 200, L = 52, R = 16, Tp = 10, B = 26;
  const ys = pts.map(p => p[1]), ymax = Math.max(...ys) * 1.15 || 1;
  const x = i => L + (i / (pts.length - 1)) * (W - L - R), y = v => Tp + (1 - v / ymax) * (H - Tp - B);
  let s = '';
  for (let k = 0; k <= 3; k++) {
    const v = (ymax * k) / 3;
    s += `<line class="grid-l" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text x="${L - 8}" y="${y(v) + 4}" text-anchor="end">${fmt(v)}</text>`;
  }
  pts.forEach((p, i) => (s += `<text x="${x(i)}" y="${H - 6}" text-anchor="middle">${p[0]}</text>`));
  s += `<path fill="none" stroke="var(--tuned)" stroke-width="2" d="${pts.map((p, i) => (i ? 'L' : 'M') + x(i) + ' ' + y(p[1])).join(' ')}"/>`;
  pts.forEach((p, i) => {
    const on = p[0] === chosen;
    s += `<circle cx="${x(i)}" cy="${y(p[1])}" r="${on ? 7 : 4}" fill="${on ? 'var(--tuned)' : 'var(--card)'}" stroke="var(--tuned)" stroke-width="2"/>
      <circle cx="${x(i)}" cy="${y(p[1])}" r="14" fill="transparent" data-tip="${p[0]} sites: <b>${fmt(p[1])}</b>${on ? ' · chosen' : ''}"/>`;
  });
  svg.innerHTML = s;
}

// Diverging bars: held weight to the left of zero, failed weight to the right.
function weightBars(svg, w) {
  const W = svg.clientWidth || 500, H = svg.clientHeight || 220, L = 150, R = 50, rows = Object.keys(w);
  const max = Math.max(...rows.flatMap(k => [Math.abs(w[k].fail), Math.abs(w[k].hold)]), 2.1);
  const x = v => L + ((v + max) / (2 * max)) * (W - L - R), band = (H - 20) / rows.length;
  let s = `<line class="grid-l" x1="${x(0)}" x2="${x(0)}" y1="0" y2="${H - 20}"/>`;
  rows.forEach((k, i) => {
    const yc = i * band + band / 2, h = 14;
    s += `<text x="0" y="${yc + 4}" style="fill:var(--text);font-size:13px">${NAME[k]}</text>`;
    s += `<rect x="${x(w[k].hold)}" y="${yc - h - 2}" width="${x(0) - x(w[k].hold)}" height="${h}" rx="4" fill="var(--clear)" data-tip="${k.toUpperCase()} held: <b>${sgn(w[k].hold)}</b>"/>`;
    s += `<rect x="${x(0)}" y="${yc + 2}" width="${x(w[k].fail) - x(0)}" height="${h}" rx="4" fill="var(--alert)" data-tip="${k.toUpperCase()} failed: <b>${sgn(w[k].fail)}</b>"/>`;
    s += `<text x="${x(w[k].hold) - 6}" y="${yc - 5}" text-anchor="end">${sgn(w[k].hold)}</text><text x="${x(w[k].fail) + 6}" y="${yc + 14}">${sgn(w[k].fail)}</text>`;
  });
  s += `<text x="${x(0)}" y="${H - 4}" text-anchor="middle">0</text>`;
  svg.innerHTML = s;
}

function draw() {
  const m = T.measured, w = T.weights, chosenRow = T.rows.find(r => r.min_sites === T.chosen);
  $('#rates').innerHTML = Object.keys(m).map(k => `
    <div class="bar"><span>${NAME[k]}</span><span class="track"><span class="fill" style="width:${m[k].p0 * 100}%;background:var(--clear)"></span></span><span class="val">${pct(m[k].p0, 1)}</span></div>
    <div class="bar"><span></span><span class="track"><span class="fill" style="width:${m[k].p1 * 100}%;background:var(--alert)"></span></span><span class="val">${pct(m[k].p1, 1)}</span></div>`).join('');
  weightBars($('#weights'), w);
  const sum = w.a.hold + w.b.fail + w.d.hold, cap = chosenRow.cap;
  $('#example').innerHTML = `<tr><td>A held</td><td class="num-c mono">${sgn(w.a.hold)}</td></tr><tr><td>B failed</td><td class="num-c mono">${sgn(w.b.fail)}</td></tr>
    <tr><td>D held</td><td class="num-c mono">${sgn(w.d.hold)}</td></tr><tr><td><b>Tuned step</b></td><td class="num-c mono"><b>${sgn(Math.max(-cap, Math.min(cap, sum)))}</b></td></tr>
    <tr><td class="muted">Plan step (any change)</td><td class="num-c mono muted">+2.08</td></tr>`;
  line($('#c-fp'), T.rows.map(r => [r.min_sites, r.false_alert]), v => pct(v, 1), T.chosen);
  line($('#c-sites'), T.rows.map(r => [r.min_sites, r.sites_to_alert]), v => v.toFixed(1), T.chosen);
  $('#rule').textContent = `We chose ${T.chosen}: ${T.rule}.`;
  $('#sweep-meta').textContent = `${T.trials.toLocaleString()} tests for each value`;
  $('#sweep').innerHTML = T.rows.map(r => `<tr class="${r.min_sites === T.chosen ? 'sel' : ''}"><td>${r.min_sites === 1 ? '1 (no real cap)' : r.min_sites}${r.min_sites === T.chosen ? ' <span class="pill clear">chosen</span>' : ''}</td>
    <td class="num-c mono">±${r.cap.toFixed(2)}</td><td class="num-c mono">${pct(r.false_alert)}</td><td class="num-c mono">${pct(r.detection)}</td><td class="num-c mono">${r.sites_to_alert.toFixed(1)}</td></tr>`).join('');
  vs($('#r-fp'), pct(T.plan.false_alert, 1), pct(chosenRow.false_alert), 'Plan method', 'Tuned method');
  vs($('#r-det'), pct(T.plan.detection, 1), pct(chosenRow.detection, 1), 'Plan method', 'Tuned method');
  vs($('#r-sites'), T.plan.sites_to_alert.toFixed(1), chosenRow.sites_to_alert.toFixed(1), 'Plan method', 'Tuned method');
  if (real) vs($('#r-real'), real.plan.false_alerts, real.tuned.false_alerts, `Plan method, of ${real.clean} clean clients`, `Tuned method, of ${real.clean} clean clients`);
}

hoverTip($('#c-fp'));
hoverTip($('#c-sites'));
hoverTip($('#weights'));
show(location.hash.slice(1));
Promise.all([api('/api/tune'), api('/api/replay?n=128')]).then(([t, r]) => { T = t; real = { ...r.compare, clean: r.clients.length - r.intercepted.length }; draw(); });
addEventListener('resize', () => T && draw());
