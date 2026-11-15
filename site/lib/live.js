// Live capture: real TLS handshakes to hosts the user names, recorded with tcpdump in a Vercel Sandbox VM and parsed
// by the C++ sensor (lib/capture.sh). The decision runs here, in the same engine as the rest of the site.
import { readFileSync } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { isIPv4 } from 'node:net';
import { Sandbox } from '@vercel/sandbox';
import { Baseline, Trw, runEvents, METHODS } from './engine.js';
import { SNAPSHOT } from './snapshot.js';

export const MIN_SITES = METHODS.tuned.min_sites, MAX_SITES = 8;
const SCRIPT = readFileSync(new URL('./capture.sh', import.meta.url));

// Private, loopback, link-local (the sandbox gateway is 169.254.0.1), CGNAT, multicast and reserved IPv4 ranges.
const BLOCKED = [[0, 8], [10, 8], [100.64, 10], [127, 8], [169.254, 16], [172.16, 12], [192.168, 16], [224, 3]].map(([a, bits]) => {
  const [x, y = 0] = String(a).split('.').map(Number);
  return [((x << 24) | (y << 16)) >>> 0, bits];
});
const toInt = ip => ip.split('.').reduce((n, o) => ((n << 8) | Number(o)) >>> 0, 0);
export const blocked = ip => BLOCKED.some(([net, bits]) => toInt(ip) >>> (32 - bits) === net >>> (32 - bits));

// "https://Example.com/path", "example.com:443" or "1.1.1.1" -> "example.com" / "1.1.1.1". Throws on anything else.
export function parseHost(s) {
  const t = String(s).trim().toLowerCase();
  let h;
  try { h = new URL(/^[a-z]+:\/\//.test(t) ? t : `https://${t}`).hostname; } catch { h = ''; }
  if (!isIPv4(h) && !/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(h))
    throw new Error(`"${String(s).slice(0, 60)}" is not a host name or an IPv4 address`);
  return h;
}

// Checks the list at the trust boundary: 3..8 distinct public hosts, each resolving only to public IPv4 addresses.
export async function checkHosts(list) {
  if (!Array.isArray(list)) throw new Error('sites must be a list');
  const hosts = [...new Set(list.filter(x => String(x).trim()).map(parseHost))];
  if (hosts.length < MIN_SITES) throw new Error(`Give at least ${MIN_SITES} different sites. The test needs ${MIN_SITES} sites to decide.`);
  if (hosts.length > MAX_SITES) throw new Error(`Give at most ${MAX_SITES} sites.`);
  await Promise.all(hosts.map(async h => {
    const ips = isIPv4(h) ? [h] : (await lookup(h, { all: true, family: 4 }).catch(() => [])).map(a => a.address);
    if (!ips.length) throw new Error(`${h} has no IPv4 address`);
    if (ips.some(blocked)) throw new Error(`${h} is a private or reserved address`);
  }));
  return hosts;
}

// Boots a VM from the snapshot, captures both passes, returns the sensor's observations and the two PCAPs.
export async function capture(hosts, path) {
  const t0 = Date.now();
  const sb = await Sandbox.create({ source: { type: 'snapshot', snapshotId: SNAPSHOT.id }, persistent: false, timeout: 120_000,
    resources: { vcpus: 2 } });
  try {
    const boot_s = (Date.now() - t0) / 1000;
    await sb.writeFiles([{ path: '/vercel/sandbox/capture.sh', content: SCRIPT }]);
    const r = await sb.runCommand({ cmd: 'bash', args: ['/vercel/sandbox/capture.sh', path, ...hosts], sudo: true });
    const log = (await r.stdout()) + (await r.stderr());
    if (r.exitCode !== 0) throw new Error(`capture failed: ${log.slice(-400)}`);
    const read = async f => (await sb.readFileToBuffer({ path: `/vercel/sandbox/out/${f}` })) ?? Buffer.alloc(0);
    const [learn, test, lp, tp] = await Promise.all(['learn.json', 'test.json', 'learn.pcap', 'test.pcap'].map(read));
    const status = Object.fromEntries(hosts.map(h => [h, {}]));
    for (const [, pcap, h, code] of log.matchAll(/out\/(learn|test)\.pcap (\S+) (\d+)/g)) status[h][pcap] = Number(code);
    return { learn: JSON.parse(learn), test: JSON.parse(test), pcaps: { learn: lp, test: tp }, status, boot_s,
      capture_s: (Date.now() - t0) / 1000 - boot_s };
  } finally {
    await sb.stop().catch(() => {});
  }
}

// Baseline from the learn pass, TRW over the test pass, for both methods. Same loop as /api/lab.
export function decide(learn, test) {
  const base = new Baseline();
  learn.forEach(o => base.learn(o));
  return Object.fromEntries(Object.entries(METHODS).map(([name, p]) => {
    const t0 = process.hrtime.bigint(), events = runEvents(test, base, p), engine_us = Number(process.hrtime.bigint() - t0) / 1000;
    return [name, { params: new Trw(p).params(), events, decisions: events.filter(e => e.decision !== 'pending'), engine_us,
      per_handshake_us: engine_us / Math.max(1, test.length) }];
  }));
}
