import { Baseline, Trw, runEvents, METHODS } from '../lib/engine.js';
import { LAB } from '../lib/lab.js';
// GET /api/lab?scenario=learn|normal|onechange|multichange|attack&method=tuned|plan
// Runs the engine over the observations the C++ sensor parsed from lab/pcaps/<scenario>.pcap.
export default function handler(req, res) {
  const scenario = String(req.query.scenario || ''), p = METHODS[req.query.method] ?? METHODS.tuned;
  if (!(scenario in LAB)) return res.status(400).json({ error: 'unknown scenario' });
  const base = new Baseline();
  LAB.learn.forEach(o => base.learn(o));
  res.setHeader('Cache-Control', 'public, s-maxage=86400');
  if (scenario === 'learn')
    return res.status(200).json({ scenario, sites: [...base.sites].map(([site, s]) => ({ site, ja4s: [...s.ja4s], keys: [...s.keys], ttl: s.ttl })) });
  const t0 = process.hrtime.bigint(), events = runEvents(LAB[scenario], base, p), us = Number(process.hrtime.bigint() - t0) / 1000;
  res.status(200).json({ scenario, method: p.weighted ? 'tuned' : 'plan', params: new Trw(p).params(), events,
    decisions: events.filter(e => e.decision !== 'pending'), engine_us: us });
}
