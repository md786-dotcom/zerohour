import { checkHosts, capture, decide } from '../lib/live.js';
import { SNAPSHOT } from '../lib/snapshot.js';

// POST /api/capture {sites: ["example.com", "1.1.1.1", ...], path: "direct"|"mitm"}
// Records real handshakes to 3..8 public hosts in a fresh Vercel Sandbox VM: a learn pass, then a test pass
// either direct or through mitmproxy on the client's gateway. Returns both PCAPs, the C++ sensor's parse, and the verdict.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'use POST' });
  const path = req.body?.path === 'mitm' ? 'mitm' : 'direct';
  let hosts;
  try { hosts = await checkHosts(req.body?.sites); } catch (e) { return res.status(400).json({ error: e.message }); }
  try {
    const c = await capture(hosts, path);
    res.status(200).json({ path, hosts, status: c.status, learn: c.learn, test: c.test, ...decide(c.learn, c.test),
      pcaps: { learn: c.pcaps.learn.toString('base64'), test: c.pcaps.test.toString('base64') },
      timing: { boot_s: c.boot_s, capture_s: c.capture_s }, sensor: SNAPSHOT.commit });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: `Live capture failed: ${e.message}` });
  }
}
