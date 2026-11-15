import { learn, test, stopVm } from '../lib/live.js';

// POST /api/live, one JSON body per step of the live page:
//   {action: "learn", sites: ["example.com", "1.1.1.1", ...], vm?}  new VM, one visit per site -> the baseline
//   {action: "test", vm, intercept: ["example.com", ...]}             visit again; listed sites go through mitmproxy
//   {action: "stop", vm}                                              stop the VM
// learn and test stream one JSON line per event (application/x-ndjson), so the page shows each handshake as it lands.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'use POST' });
  let b;
  try { b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body ?? {}; } catch { return res.status(400).json({ error: 'bad JSON' }); }
  if (b.action === 'stop') {
    await stopVm(b.vm).catch(() => {});
    return res.status(204).end();
  }
  const steps = b.action === 'learn' ? learn(b.sites, b.vm) : b.action === 'test' ? test(b.vm, b.intercept) : null;
  if (!steps) return res.status(400).json({ error: 'action must be learn, test or stop' });
  // The page closed or reloaded: end the generator, so its finally blocks stop the new VM or unlock the VM and save its log.
  let gone = false;
  res.on('close', () => { if (!res.writableEnded) gone = true; });
  let first;
  try { first = await steps.next(); } catch (e) { return res.status(400).json({ error: e.message }); }  // bad input or no VM
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.write(JSON.stringify(first.value) + '\n');
  try {
    for await (const e of steps) {
      if (gone) break;  // break calls steps.return()
      res.write(JSON.stringify(e) + '\n');
    }
  } catch (e) {
    console.error(e);
    res.write(JSON.stringify({ type: 'error', error: e.message }) + '\n');
  }
  res.end();
}
