import { verifyChain } from '../lib/engine.js';
// POST /api/verify {records:[{seq,prev,payload,hash}]}: recomputes every hash and link of the records sent.
export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  const records = req.body?.records;
  if (!Array.isArray(records) || records.length > 1000) return res.status(400).json({ error: 'need records: array of at most 1000' });
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json(verifyChain(records));
}
