import { openSync, writeSync, fsyncSync, closeSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Baseline, Trw, Chain, METHODS, percentile } from '../lib/engine.js';
import { LAB, BUSY_INTERCEPTED, BUSY_TIMES } from '../lib/lab.js';

// GET /api/replay?n=K&method=tuned|plan
// Replays the first K handshakes of lab/pcaps/busy.pcap (8 clients, 16 sites each, 2 behind an interceptor) against
// the baseline from busylearn.pcap. Stateless: the page asks for a growing K while it runs.
// Detection time: the C++ sensor's measured time for each of these handshakes (zerohour bench, durable log on an
// Apple M2 disk), averaged over the first K. The engine is also timed here, with its log fsync'd to this server's /tmp
// (plan: every record, tuned: alerts only); /tmp is a fast scratch disk, so that number is shown only as a side note.
export default function handler(req, res) {
  const obs = LAB.busy, n = Math.max(0, Math.min(obs.length, Math.floor(Number(req.query.n) || 0)));
  const method = req.query.method === 'plan' ? 'plan' : 'tuned', base = new Baseline(), truth = new Set(BUSY_INTERCEPTED);
  LAB.busylearn.forEach(o => base.learn(o));
  const runs = {};
  for (const [name, p] of Object.entries(METHODS)) {
    const timed = name === method, path = join(tmpdir(), `zh-${process.pid}-${Date.now()}-${name}.log`);
    const fd = timed ? openSync(path, 'a') : -1;
    const trw = new Trw(p), chain = new Chain(), events = [], verdict = new Map(), lat = [];
    try {
      for (const o of obs.slice(0, n)) {
        const t0 = process.hrtime.bigint();
        const c = base.check(o, p.ttl_delta), s = trw.observe(o.client, o.site, trw.step(c)), changed = c.a || c.b || c.d;
        const payload = s.decision !== 'pending'
          ? { type: s.decision, client: o.client, sites: s.sites, score: +s.score.toFixed(4) }
          : changed && s.counted ? { type: 'notice', client: o.client, site: o.site, score: +s.score.toFixed(4) } : null;
        if (payload) {
          const rec = chain.append(JSON.stringify(payload));
          if (timed) {
            writeSync(fd, chain.line(rec));
            if (p.weighted ? s.decision === 'alert' : true) fsyncSync(fd);
          }
        }
        if (timed) lat.push(Number(process.hrtime.bigint() - t0) / 1000);
        if (s.decision !== 'pending') verdict.set(o.client, s.decision === 'alert' || verdict.get(o.client) === 'alert' ? 'alert' : 'clear');
        events.push({ client: o.client, site: o.site, checks: { A: c.a, B: c.b_seen ? c.b : null, D: c.d }, delta: s.delta, score: s.score,
          decision: s.decision, truth: truth.has(o.client) });
      }
    } finally {
      if (timed) { closeSync(fd); rmSync(path, { force: true }); }
    }
    const clients = [...new Set(obs.map(o => o.client))].map(ip => ({ ip, intercepted: truth.has(ip), score: trw.score(ip),
      sites: trw.sitesIn(ip), verdict: verdict.get(ip) ?? 'testing' }));
    const alerted = clients.filter(c => c.verdict === 'alert');
    runs[name] = { clients, events, chain, lat, caught: alerted.filter(c => c.intercepted).length, false_alerts: alerted.filter(c => !c.intercepted).length };
  }
  const run = runs[method], lat = run.lat;
  res.setHeader('Cache-Control', 'no-store');  // timings are measured per request
  res.status(200).json({ n, total: obs.length, method, params: new Trw(METHODS[method]).params(), intercepted: BUSY_INTERCEPTED,
    clients: run.clients, events: run.events.slice(-12).reverse(),
    timing: (() => {
      const cpp = BUSY_TIMES[method].slice(0, n), mean = v => (v.length ? v.reduce((a, b) => a + b, 0) / v.length : 0);
      return { n: cpp.length, mean_us: mean(cpp), p99_us: percentile(cpp, 0.99), budget_us: 4000,
        flush: method === 'plan' ? 'every record' : 'alerts only', server_mean_us: mean(lat) };
    })(),
    compare: Object.fromEntries(Object.entries(runs).map(([k, v]) => [k, { caught: v.caught, false_alerts: v.false_alerts }])),
    log: { records: run.chain.records.length, algorithm: 'BLAKE2b-256', tail: run.chain.records.slice(-10) } });
}
