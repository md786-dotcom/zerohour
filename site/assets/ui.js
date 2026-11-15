// Shared helpers for both pages.
export const $ = (s, el = document) => el.querySelector(s);
// Server names and fingerprints come from (simulated) packets: always escape before innerHTML.
export const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
export const sgn = (x, d = 2) => (x >= 0 ? '+' : '−') + Math.abs(Number(x) + Math.sign(x) * 1e-9).toFixed(d);
export const pct = (x, d = 3) => (x * 100).toFixed(d) + '%';
export const us = x => (x >= 1000 ? (x / 1000).toFixed(2) + ' ms' : x >= 10 ? x.toFixed(0) + ' µs' : x.toFixed(2) + ' µs');
export const clock = t => new Date(t * 1000).toLocaleTimeString([], { hour12: false });

export async function api(path, opts) {
  const r = await fetch(path, opts);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}

export const chips = c => `<span class="chips">${['A', 'B', 'D'].map(k => {
  const v = c?.[k], label = { A: 'server fingerprint (JA4S)', B: 'certificate key', D: 'network path (TTL)' }[k];
  return `<span class="chip${v ? ' bad' : v === null ? ' na' : ''}" title="${k}: ${label} ${v ? 'changed' : v === null ? 'not visible (TLS 1.3)' : 'same'}">${k}</span>`;
}).join('')}</span>`;

const tip = Object.assign(document.createElement('div'), { className: 'tip', hidden: true });
document.body.append(tip);
export function hoverTip(el) {
  el.addEventListener('pointermove', e => {
    const t = e.target.closest('[data-tip]');
    if (!t) { tip.hidden = true; return; }
    tip.innerHTML = t.dataset.tip;
    tip.hidden = false;
    const x = Math.min(e.clientX + 14, innerWidth - tip.offsetWidth - 8);
    tip.style.left = x + 'px';
    tip.style.top = e.clientY + 14 + 'px';
  });
  el.addEventListener('pointerleave', () => (tip.hidden = true));
}

// Score walk: series [{name, color, dash, pts: [[site, score, result]]}] against the alert/clear thresholds.
export function walkChart(svg, series, { upper, lower, xlabel = 'sites counted in the test', xmax: xmin = 6 }) {
  const W = svg.clientWidth || 640, H = svg.clientHeight || 280, L = 40, R = 76, T = 14, B = 34;
  const all = series.flatMap(s => s.pts);
  const xmax = Math.max(xmin, ...all.map(p => p[0]));
  const ymax = Math.max(upper, ...all.map(p => p[1])) + 1, ymin = Math.min(lower, ...all.map(p => p[1])) - 1;
  const x = v => L + (v / xmax) * (W - L - R), y = v => T + ((ymax - v) / (ymax - ymin)) * (H - T - B);
  let s = '';
  for (let v = Math.ceil(ymin / 2) * 2; v <= ymax; v += 2)
    s += `<line class="grid-l" x1="${L}" x2="${x(xmax)}" y1="${y(v)}" y2="${y(v)}"/><text x="${L - 8}" y="${y(v) + 4}" text-anchor="end">${v}</text>`;
  for (let i = 1; i <= xmax; i++) s += `<text x="${x(i)}" y="${H - 14}" text-anchor="middle">${i}</text>`;
  s += `<text x="${(L + x(xmax)) / 2}" y="${H - 1}" text-anchor="middle">${esc(xlabel)}</text>`;
  for (const [v, label, col] of [[upper, 'alert', 'var(--alert)'], [lower, 'clear', 'var(--clear)']])
    s += `<line class="thr" stroke="${col}" x1="${L}" x2="${x(xmax)}" y1="${y(v)}" y2="${y(v)}"/><text x="${x(xmax) + 6}" y="${y(v) + 4}">${sgn(v)} ${label}</text>`;
  for (const { name, color, dash, pts } of series) {
    s += `<path fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"${dash ? ` stroke-dasharray="${dash}"` : ''}
      d="${pts.map((p, i) => (i ? 'L' : 'M') + x(p[0]).toFixed(1) + ' ' + y(p[1]).toFixed(1)).join(' ')}"/>`;
    for (const [a, b, r] of pts.slice(1))
      s += `<circle cx="${x(a)}" cy="${y(b)}" r="${r === 'mismatch' ? 5 : 4}" fill="${r === 'mismatch' ? color : 'var(--card)'}" stroke="${color}" stroke-width="2"/>
        <circle cx="${x(a)}" cy="${y(b)}" r="12" fill="transparent" data-tip="<b>${esc(name)}</b> · site ${a}<br>${esc(r)} · score ${sgn(b)}"/>`;
  }
  svg.innerHTML = s;
}
