import { $, esc, sgn, api } from './ui.js';

// Evidence log tab: BLAKE2b-256, computed in this browser. Used by the demo (live replay) and the live page (the VM's log).
// The page has the markup: #log, #log-sub, #verify, #tamper, #verify-result.
// view: every record on screen, oldest first (a copy, so "Change one record" can edit one). Verify recomputes each
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

// records(): the records to show; sub(count): the line under the title; empty: what Verify says with no records.
export function evidenceLog({ records, sub, empty }) {
  let view = null, blake;
  function render() {
    const recs = view ?? records();
    $('#log-sub').textContent = sub(recs.length);
    $('#log').innerHTML = recs.map(r => logRow(r, null)).join('') || '<tr><td colspan="6" class="muted">No records yet.</td></tr>';
  }
  async function verify(edit) {
    if (!records().length) { $('#verify-result').textContent = empty; return; }
    for (const b of [$('#verify'), $('#tamper')]) b.disabled = true;
    try {
      blake ??= (await import('./blake2b.js')).default;
      const cur = (view = records().map(r => ({ ...r }))); // render() shows view; this run keeps cur even if reset() clears view
      if (edit) {  // an attacker hides an alert: rewrite one record, keep its old hash
        const r = cur.find(x => x.payload.includes('"alert"')) ?? cur[Math.floor(cur.length / 2)];
        r.payload = r.payload.replace(/"type":"\w+"/, '"type":"clear"').replace(/"score":-?[\d.]+/, '"score":-5');
        r.edited = true;
      }
      render();
      const rows = [...$('#log').children], out = $('#verify-result');
      let last = cur[0].seq === 1 ? ZERO : cur[0].prev, bad = 0, total = 0;
      for (const [i, r] of cur.entries()) {
        rows[i].outerHTML = logRow(r, { run: true });
        const row = $('#log').children[i];
        row.scrollIntoView({ block: 'nearest' });
        out.innerHTML = `<span class="muted">Computing BLAKE2b-256 of record ${r.seq} of ${cur.length}…</span>`;
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
        body: JSON.stringify({ records: cur.map(({ seq, prev, payload, hash }) => ({ seq, prev, payload, hash })) }) });
      const agree = v.bad_record === bad ? 'The server agrees.' : `The server found record ${v.bad_record}.`;
      out.innerHTML = bad ? `<span class="pill alert">Record ${bad} is incorrect: its hash does not match. ${agree}</span>`
        : `<span class="pill clear">Log is correct: ${cur.length} records, BLAKE2b-256, ${(total / 1000).toFixed(2)} ms of hashing. ${agree}</span>`;
      if (bad) $(`#log tr[data-seq="${bad}"]`).scrollIntoView({ block: 'center' });
    } catch (e) { $('#verify-result').textContent = e.message; }
    finally { for (const b of [$('#verify'), $('#tamper')]) b.disabled = false; }
  }
  $('#verify').addEventListener('click', () => verify(false));
  $('#tamper').addEventListener('click', () => verify(true));
  return { render, reset() { view = null; } };
}
