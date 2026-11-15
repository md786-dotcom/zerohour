import { measured, weights, sweep } from '../lib/tune.js';
// GET /api/tune: the three tuning steps (measure, weigh, cap) computed from the traffic model.
export default function handler(req, res) {
  res.setHeader('Cache-Control', 'public, s-maxage=86400');
  res.status(200).json({ measured: measured(), weights: weights(), ...sweep() });
}
