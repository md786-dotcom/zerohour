// Live capture: real TLS handshakes to hosts the user names, recorded with tcpdump in a Vercel Sandbox VM and parsed
// by the C++ sensor (lib/capture.sh). One VM is one client network: step 1 learns, then any number of tests reuse it.
// The decision runs here, in the same engine as the rest of the site (tuned method), one handshake at a time.
import { readFileSync } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { isIPv4 } from 'node:net';
import { Sandbox } from '@vercel/sandbox';
import { Baseline, Trw, Chain, METHODS, percentile, hash } from './engine.js';
import { SNAPSHOT } from './snapshot.js';

const P = METHODS.tuned;
export const MIN_SITES = P.min_sites, MAX_SITES = 8, CLIENT = '10.9.0.2';
const TAG = { app: 'zerohour-live' }, MAX_VMS = 4;  // the page is public: cap the VMs that run at one time
const SCRIPT = readFileSync(new URL('./capture.sh', import.meta.url));
const OUT = '/vercel/sandbox/out';
hash('', 0, '');  // a running sensor is warm: compile BLAKE2b once here, not inside the first timed handshake

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

// Runs one capture.sh subcommand. The VM's output stays in the server log; the caller gets a short message.
// The lock subcommand's own message ("A test is running") is safe and useful, so it goes through.
async function sh(sb, args) {
  const r = await sb.runCommand({ cmd: 'bash', args: ['/vercel/sandbox/capture.sh', ...args], sudo: true });
  const out = await r.stdout();
  if (r.exitCode !== 0) {
    const err = await r.stderr();
    console.error(`capture.sh ${args[0]} exit ${r.exitCode}: ${(out + err).slice(-2000)}`);
    throw new Error(r.exitCode === 3 ? err.trim() : `The VM step "${args[0]}" failed.`);
  }
  return out;
}
const readJson = async (sb, f, empty) => {
  const b = await sb.readFileToBuffer({ path: `${OUT}/${f}` });
  return b ? JSON.parse(b.toString()) : empty;
};
const writeJson = (sb, f, v) => sb.writeFiles([{ path: `${OUT}/${f}`, content: Buffer.from(JSON.stringify(v)) }]);
const pcapB64 = async (sb, f) => ((await sb.readFileToBuffer({ path: `${OUT}/${f}` })) ?? Buffer.alloc(0)).toString('base64');
const STOPPED = 'The VM stopped. Do step 1 (Learn) again.';

async function openVm(name) {
  if (!/^[a-z0-9][a-z0-9-]{2,80}$/i.test(String(name ?? ''))) throw new Error('No VM yet. Do step 1 (Learn) first.');
  const sb = await Sandbox.get({ name, resume: false }).catch(() => null);
  if (sb?.status !== 'running') throw new Error(STOPPED);
  return sb;
}
export async function stopVm(name) {
  const sb = await openVm(name).catch(() => null);
  await sb?.stop();
}

// One HTTPS visit per site while tcpdump records <pcap>. Yields each visit with the handshake the C++ sensor parsed
// for it (null when the site gave none).
async function* visits(sb, sites, pcap) {
  await sh(sb, ['start', `${OUT}/${pcap}`]);
  try {
    for (const s of sites) {
      if (!s.ip) { yield { host: s.host, code: 0, obs: null }; continue; }
      const out = await sh(sb, ['visit', s.host, `${OUT}/${pcap}`]), nl = out.indexOf('\n');
      const all = JSON.parse(out.slice(nl + 1));
      yield { host: s.host, ip: s.ip, code: Number(out.slice(0, nl)), obs: all.findLast(o => o.site === s.host) ?? null };
    }
  } finally {
    await sh(sb, ['stop']).catch(() => {});
  }
}

// Step 1: a new VM, then one visit per site. The handshakes are the baseline for every later test in this VM.
// The VM is stopped on every way out except success, also when the caller stops reading (generator return).
export async function* learn(list, oldVm) {
  const hosts = await checkHosts(list);
  if (oldVm) await stopVm(oldVm).catch(() => {});
  const live = (await Sandbox.list({ tags: TAG, sortBy: 'createdAt', sortOrder: 'desc', limit: 20 })).sandboxes
    .filter(s => s.status === 'pending' || s.status === 'running').length;
  if (live >= MAX_VMS) throw new Error(`${live} live VMs are running now. Try again in a few minutes.`);
  const t0 = Date.now();
  const sb = await Sandbox.create({ source: { type: 'snapshot', snapshotId: SNAPSHOT.id }, persistent: false, timeout: 15 * 60_000,
    resources: { vcpus: 2 }, tags: TAG });
  let ok = false;
  try {
    await sb.writeFiles([{ path: '/vercel/sandbox/capture.sh', content: SCRIPT }]);
    const sites = (await sh(sb, ['setup', ...hosts])).trim().split('\n').map(l => {
      const [host, ip] = l.split(' ');
      return { host, ip: ip === '-' ? null : ip };
    });
    const bad = sites.find(s => s.ip && blocked(s.ip));  // the VM resolves again: check its answer too
    if (bad) throw new Error(`${bad.host} is a private or reserved address`);
    await writeJson(sb, 'sites.json', sites);
    yield { type: 'vm', vm: sb.name, client: CLIENT, sites, boot_s: (Date.now() - t0) / 1000, sensor: SNAPSHOT.commit };
    const learned = [];
    let i = 0;
    for await (const v of visits(sb, sites, 'learn.pcap')) {
      if (v.obs) learned.push(v.obs);
      yield { type: 'handshake', i: ++i, total: sites.length, ...v };
    }
    await writeJson(sb, 'learn.json', learned);
    ok = true;
    yield { type: 'done', learned: learned.length, total: sites.length, pcap: await pcapB64(sb, 'learn.pcap'), params: new Trw(P).params() };
  } finally {
    if (!ok) await sb.stop().catch(() => {});
  }
}

// Step 2: the client visits every site again. Sites in `intercept` go through mitmproxy on the gateway (sites with
// the same IPv4 address go together). Each handshake is checked against the baseline and moves the tuned TRW score.
// Notices and verdicts go to the VM's log; the log is saved on every way out, so a verdict the page saw is never lost.
export async function* test(name, intercept) {
  const sb = await openVm(name);
  // A VM that stopped is resumed by the SDK as an empty new session: it has no capture.sh. Stop that one at once.
  if (!(await sb.readFileToBuffer({ path: '/vercel/sandbox/capture.sh' }).catch(() => null))) {
    await sb.stop().catch(() => {});
    throw new Error(STOPPED);
  }
  await sh(sb, ['lock']);
  let chain = null;
  try {
    await sb.extendTimeout(5 * 60_000).catch(() => {});  // fails past the plan's session cap; the VM then stops on its own
    const [sites, learned, records, runs] = await Promise.all([readJson(sb, 'sites.json', []), readJson(sb, 'learn.json', null),
      readJson(sb, 'chain.json', []), readJson(sb, 'runs.json', 0)]);
    if (!learned) throw new Error('Do step 1 (Learn) first.');
    const want = new Set(Array.isArray(intercept) ? intercept.map(String) : []);
    const via = new Set(sites.filter(s => s.ip && want.has(s.host)).map(s => s.ip));
    await sh(sb, ['route', ...via]);
    const run = runs + 1, pcap = `test-${run}.pcap`, base = new Baseline(), trw = new Trw(P), lat = [], decisions = [];
    learned.forEach(o => base.learn(o));
    chain = new Chain();
    chain.records = records;
    await writeJson(sb, 'runs.json', run);
    yield { type: 'start', run, total: sites.length, intercepted: sites.filter(s => via.has(s.ip)).map(s => s.host), params: trw.params() };
    let i = 0;
    for await (const v of visits(sb, sites, pcap)) {
      const ev = { type: 'handshake', i: ++i, total: sites.length, host: v.host, code: v.code, intercepted: via.has(v.ip), obs: v.obs };
      if (v.obs) {
        // Timed: check against the baseline, TRW step, and the log record in memory. The C++ parse in the VM is not in it.
        const o = v.obs, t0 = process.hrtime.bigint(), c = base.check(o, P.ttl_delta);
        const s = c.known ? trw.observe(o.client, o.site, trw.step(c)) : null;
        if (s) {
          const payload = s.decision !== 'pending' ? { type: s.decision, client: o.client, sites: s.sites, score: +s.score.toFixed(4) }
            : (c.a || c.b || c.d) && s.counted ? { type: 'notice', client: o.client, site: o.site, score: +s.score.toFixed(4) } : null;
          if (payload) chain.append(JSON.stringify(payload));
        }
        const us = Number(process.hrtime.bigint() - t0) / 1000;
        lat.push(us);
        Object.assign(ev, { known: c.known, checks: { A: c.a, B: c.b_seen ? c.b : null, D: c.d }, us,
          ...(s ? { delta: s.delta, score: s.score, sites: s.sites, decision: s.decision } : { delta: 0, decision: 'pending' }) });
        if (s && s.decision !== 'pending') decisions.push({ decision: s.decision, sites: s.sites, score: s.score, at: i });
      }
      yield ev;
    }
    await writeJson(sb, 'chain.json', chain.records);
    yield { type: 'done', run, decisions, pcap: await pcapB64(sb, pcap), log: chain.records,
      timing: { n: lat.length, mean_us: lat.reduce((a, b) => a + b, 0) / Math.max(1, lat.length), p99_us: percentile(lat, 0.99), budget_us: 4000 } };
  } finally {
    if (chain) await writeJson(sb, 'chain.json', chain.records).catch(() => {});
    await sh(sb, ['unlock']).catch(() => {});
  }
}
