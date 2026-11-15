import { Baseline, Trw, Chain, METHODS } from '../lib/engine.js';
import { LAB, BUSY_INTERCEPTED } from '../lib/lab.js';
// GET /api/replay?n=K&method=tuned|plan
// Replays the first K handshakes of lab/pcaps/busy.pcap (8 clients, 2 behind an interceptor) through the engine.
// Stateless: the page asks for a growing K while it runs. Both methods run so the page can compare false alerts.
export default function handler(req, res) {
  const obs = LAB.busy, n = Math.max(0, Math.min(obs.length, Math.floor(Number(req.query.n) || 0)));
  const method = req.query.method === 'plan' ? 'plan' : 'tuned', base = new Baseline();
  LAB.learn.forEach(o => base.learn(o));
  const truth = new Set(BUSY_INTERCEPTED), runs = {};
  for (const [name, p] of Object.entries(METHODS)) {
    const trw = new Trw(p), chain = new Chain(), events = [], verdict = new Map();
    for (const o of obs.slice(0, n)) {
      const c = base.check(o, p.ttl_delta), s = trw.observe(o.client, o.site, trw.step(c)), changed = c.a || c.b || c.d;
      const payload = s.decision !== 'pending'
        ? { type: s.decision, client: o.client, sites: s.sites, score: +s.score.toFixed(4) }
        : changed && s.counted ? { type: 'notice', client: o.client, site: o.site, score: +s.score.toFixed(4) } : null;
      if (payload) chain.append(JSON.stringify(payload));
      if (s.decision !== 'pending') verdict.set(o.client, s.decision === 'alert' ? 'alert' : verdict.get(o.client) === 'alert' ? 'alert' : 'clear');
      events.push({ client: o.client, site: o.site, ja4s: o.ja4s, ttl: o.ttl, checks: { A: c.a, B: c.b_seen ? c.b : null, D: c.d },
        delta: s.delta, score: s.score, decision: s.decision, truth: truth.has(o.client) });
    }
    const clients = [...new Set(obs.map(o => o.client))].map(ip => ({ ip, intercepted: truth.has(ip), score: trw.score(ip),
      sites: trw.sitesIn(ip), verdict: verdict.get(ip) ?? 'testing' }));
    const alerted = clients.filter(c => c.verdict === 'alert');
    runs[name] = { clients, events, chain, caught: alerted.filter(c => c.intercepted).length, false_alerts: alerted.filter(c => !c.intercepted).length };
  }
  const run = runs[method];
  res.setHeader('Cache-Control', 'public, s-maxage=86400');
  res.status(200).json({ n, total: obs.length, method, params: new Trw(METHODS[method]).params(), intercepted: BUSY_INTERCEPTED,
    clients: run.clients, events: run.events.slice(-12).reverse(),
    compare: Object.fromEntries(Object.entries(runs).map(([k, v]) => [k, { caught: v.caught, false_alerts: v.false_alerts }])),
    log: { records: run.chain.records.length, tail: run.chain.records.slice(-10) } });
}
