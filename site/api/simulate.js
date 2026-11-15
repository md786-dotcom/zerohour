import { simulate } from '../lib/sim.js';
// GET /api/simulate?trials=N&seed=S: Monte Carlo of both methods (see lib/sim.js). trials capped at 200k per case.
export default function handler(req, res) {
  const trials = Math.min(200000, Math.max(1000, Number(req.query.trials) || 50000)), seed = Number(req.query.seed) || 2026;
  res.setHeader('Cache-Control', 'public, s-maxage=3600');
  res.status(200).json(simulate({ trials, seed }));
}
