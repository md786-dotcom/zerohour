import { live } from '../lib/live.js';
// GET /api/live?method=tuned|plan[&at=<unix seconds>]: the console's state, replayed from the clock.
export default function handler(req, res) {
  const at = Number(req.query.at);
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json(live(Number.isFinite(at) && at > 0 ? at : Date.now() / 1000, String(req.query.method || 'tuned')));
}
