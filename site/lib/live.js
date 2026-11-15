// Simulated campus network for the live console. Every second is a pure function of the clock (seeded PRNG), so any
// serverless instance replays the same traffic and gets the same verdicts without shared state. The handshakes are
// synthetic; the decisions come from the real engine (engine.js, parity-tested against the C++ sensor).
import { Baseline, Trw, Chain, METHODS, percentile } from './engine.js';
import { rng, MODELS } from './sim.js';

const fnv = s => { let h = 0x811c9dc5; for (const c of s) h = Math.imul(h ^ c.charCodeAt(0), 0x01000193) >>> 0; return h; };
const hex = (s, n) => { let o = ''; for (let i = 0; o.length < n; i++) o += fnv(s + i).toString(16).padStart(8, '0'); return o.slice(0, n); };

// [server name, TLS version, initial TTL of the server OS, hops]
const SITES = [
  ['login.microsoftonline.com', '1.3', 128, 14], ['outlook.office365.com', '1.3', 128, 14], ['teams.microsoft.com', '1.3', 128, 15],
  ['canvas.instructure.com', '1.3', 64, 13], ['github.com', '1.3', 64, 12], ['api.github.com', '1.3', 64, 12],
  ['stackoverflow.com', '1.3', 64, 16], ['en.wikipedia.org', '1.3', 64, 11], ['arxiv.org', '1.3', 64, 17],
  ['scholar.archive.org', '1.3', 64, 18], ['www.sciencedirect.com', '1.3', 64, 15], ['link.springer.com', '1.3', 64, 16],
  ['ieeexplore.ieee.org', '1.2', 64, 17], ['www.jstor.org', '1.2', 64, 18], ['zoom.us', '1.2', 64, 13],
  ['slack.com', '1.3', 64, 12], ['www.notion.so', '1.3', 64, 13], ['docs.python.org', '1.3', 64, 14],
  ['pypi.org', '1.3', 64, 14], ['registry.npmjs.org', '1.3', 64, 12], ['www.overleaf.com', '1.3', 64, 16],
  ['drive.google.com', '1.3', 64, 9], ['docs.google.com', '1.3', 64, 9], ['www.bbc.co.uk', '1.3', 64, 15],
  ['www.reuters.com', '1.3', 64, 14], ['www.dropbox.com', '1.3', 64, 13], ['portal.college.example', '1.2', 64, 3],
  ['library.college.example', '1.2', 64, 3], ['sis.college.example', '1.2', 64, 3], ['vpn.college.example', '1.2', 64, 2],
  ['print.college.example', '1.2', 64, 2], ['mail.college.example', '1.3', 64, 3],
].map(([name, tls, init, hops], i) => ({ name, tls, ttl: init - hops, ip: `${[13, 20, 52, 140, 151, 162, 185][i % 7]}.${(fnv(name) >> 8) & 255}.${(fnv(name) >> 16) & 255}.${fnv(name) & 255}` }));
SITES.forEach(s => { if (s.name.endsWith('.example')) s.ip = `10.20.0.${10 + (fnv(s.name) % 40)}`; });

const BROWSERS = [  // JA4 client fingerprints of common browsers
  ['Chrome 131', 't13d1516h2_8daaf6152771_02713d6af862'], ['Edge 131', 't13d1516h2_8daaf6152771_e5627efa2ab1'],
  ['Firefox 133', 't13d1715h2_5b57614c22b0_3d5424432f57'], ['Safari 18', 't13d2014h2_a09f3c656075_14788d8d241b'],
];
const GROUPS = [['LIB-WS', '10.20.1.', 8], ['ENG-LAB', '10.20.2.', 10], ['ADMIN', '10.20.3.', 6], ['WIFI-3F', '10.20.8.', 8]];
export const CLIENTS = GROUPS.flatMap(([name, net, n], g) => Array.from({ length: n }, (_, i) => ({
  name: `${name}-${String(i + 1).padStart(2, '0')}`, ip: net + (11 + g * 30 + i), browser: BROWSERS[(i + g) % 4][0],
  ja4: BROWSERS[(i + g) % 4][1] })));

const ja4s = (s, v) => (s.tls === '1.3' ? `t1302h2_130${1 + (fnv(s.name + v) % 2)}_` : `t1204h2_c0${['2f', '30', '2b'][fnv(s.name + v) % 3]}_`) + hex(s.name + 'ja4s' + v, 12);
const key = (s, v) => (s.tls === '1.2' ? hex(s.name + 'key' + v, 16) : '');
const INTERCEPTOR_JA4S = 't120300_c02c_460f64128655';  // the lab interceptor's real JA4S (lab/pcaps/attack.pcap)

// Each 4-minute cycle one client sits behind a TLS interceptor (rogue root CA) for 90 s.
export const CYCLE = 240, ATTACK_FROM = 70, ATTACK_FOR = 90;
export const victimAt = t => {
  const k = Math.floor(t / CYCLE), off = t - k * CYCLE;
  return off >= ATTACK_FROM && off < ATTACK_FROM + ATTACK_FOR ? (k * 11 + 3) % CLIENTS.length : -1;
};

const zipf = SITES.map((_, i) => 1 / (i + 1) ** 0.6), zsum = zipf.reduce((a, b) => a + b);
function pickSite(r) { let x = r() * zsum; for (let i = 0; i < SITES.length; i++) if ((x -= zipf[i]) <= 0) return SITES[i]; return SITES.at(-1); }

// All handshakes in whole seconds [from, to).
export function traffic(from, to) {
  const m = MODELS.nominal, out = [];
  for (let t = from; t < to; t++) {
    const victim = victimAt(t);
    CLIENTS.forEach((c, ci) => {
      const r = rng(fnv(`${t}:${ci}`));
      if (r() >= 1 / 9) return;  // each client opens a new TLS connection about every 9 s
      const s = pickSite(r), ts = t + r(), intercepted = ci === victim;
      let o;
      if (intercepted) o = { ja4s: INTERCEPTOR_JA4S, key: hex(s.name + 'forged', 16), ttl: 63, tls: '1.2', server: s.ip };
      else {
        const migrate = r() < m.migrate, a = migrate || r() < m.a, b = s.tls === '1.2' && (migrate || r() < m.b), d = migrate || r() < m.d;
        const jitter = Math.floor(r() * 3) - 1, moved = (r() < 0.5 ? -1 : 1) * (3 + Math.floor(r() * 6));
        o = { ja4s: ja4s(s, a ? (migrate ? 2 : 1) : 0), key: key(s, b ? (migrate ? 2 : 1) : 0), ttl: s.ttl + (d ? moved : jitter), tls: s.tls,
          server: s.ip };
      }
      out.push({ ts, client: c.ip, host: c.name, site: s.name, ja4: c.ja4, truth: intercepted, ...o });
    });
  }
  return out;
}

export function baseline() {  // learned during a clean week: each site's usual JA4S, key and TTL
  const b = new Baseline();
  for (const s of SITES) b.learn({ site: s.name, ja4s: ja4s(s, 0), key: key(s, 0), ttl: s.ttl });
  return b;
}

const WINDOW = 600, WARMUP = 120;
// Replays the last WINDOW seconds (plus warm-up) through the engine with both methods.
export function live(now, methodName = 'tuned') {
  const to = Math.floor(now), from = to - WINDOW - WARMUP, base = baseline();
  const obs = traffic(from, to);
  const runs = {};
  for (const [name, p] of Object.entries(METHODS)) {
    const trw = new Trw(p), chain = new Chain(), events = [], decisions = [], lat = [];
    const series = new Map(CLIENTS.map(c => [c.ip, []]));
    for (const o of obs) {
      const t0 = process.hrtime.bigint();
      const checks = base.check(o, p.ttl_delta);
      const s = trw.observe(o.client, o.site, trw.step(checks));
      const mismatch = checks.a || checks.b || checks.d;
      if (s.decision !== 'pending') chain.append(JSON.stringify({ type: s.decision, client: o.client, sites: s.sites, score: +s.score.toFixed(4), t: +o.ts.toFixed(3) }));
      else if (mismatch && s.counted) chain.append(JSON.stringify({ type: 'notice', client: o.client, site: o.site, score: +s.score.toFixed(4), t: +o.ts.toFixed(3) }));
      lat.push(Number(process.hrtime.bigint() - t0) / 1000);
      if (o.ts < to - WINDOW) continue;
      const ev = { ...o, checks: { A: checks.a, B: checks.b_seen ? checks.b : null, D: checks.d }, result: !s.counted ? 'repeat' : mismatch ? 'mismatch' : 'match', ...s };
      events.push(ev);
      series.get(o.client).push([+o.ts.toFixed(2), +s.score.toFixed(3), s.decision]);
      if (s.decision !== 'pending') decisions.push({ t: ev.ts, client: o.client, host: o.host, decision: s.decision, sites: s.sites, score: s.score, truth: o.truth });
    }
    const alerts = decisions.filter(d => d.decision === 'alert');
    runs[name] = { trw, chain, events, decisions, alerts, series, lat,
      summary: { alerts: alerts.length, true_alerts: alerts.filter(a => a.truth).length, false_alerts: alerts.filter(a => !a.truth).length,
        clears: decisions.length - alerts.length } };
  }
  const run = runs[methodName] ?? runs.tuned, { trw } = run, victim = victimAt(to - 1);
  return {
    now: to, window_s: WINDOW, method: methodName in METHODS ? methodName : 'tuned', params: trw.params(),
    simulated: true,
    stats: { handshakes_per_min: run.events.filter(e => e.ts >= to - 60).length, handshakes_window: run.events.length,
      clients: CLIENTS.length, sites: SITES.length,
      latency_us: { p50: percentile(run.lat, 0.5), p99: percentile(run.lat, 0.99), max: percentile(run.lat, 1), n: run.lat.length },
      budget_us: 4000 },
    compare: Object.fromEntries(Object.entries(runs).map(([k, v]) => [k, v.summary])),
    clients: CLIENTS.map((c, i) => {
      const last = run.decisions.filter(d => d.client === c.ip).at(-1);
      return { ...c, score: trw.score(c.ip), sites: trw.sitesIn(c.ip), last_decision: last ?? null,
        intercepted_now: i === victim, series: run.series.get(c.ip).slice(-24) };
    }),
    alerts: run.alerts.slice(-12).reverse(),
    events: run.events.slice(-80).reverse(),
    log: { records: run.chain.records.length, head: run.chain.records.at(-1)?.hash ?? null, tail: run.chain.records.slice(-20) },
    next_attack_in_s: (() => { for (let t = to; t < to + CYCLE; t++) if (victimAt(t) >= 0 && victimAt(t - 1) < 0) return t - to; return 0; })(),
  };
}
