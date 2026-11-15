// Decision engine of the zerohour sensor, ported 1:1 from src/trw.cpp and Baseline::check in src/sensor.cpp.
// test/parity.mjs runs both on the lab PCAPs and fails on any difference in step, score or decision.
import blakejs from 'blakejs';
const { blake2bHex } = blakejs;

// zerohour.conf (plan, "before") and zerohour.tuned.conf ("after").
export const PLAN = { theta0: 0.9, theta1: 0.2, alpha: 0.01, beta: 0.99, ttl_delta: 2, weighted: false,
  a0: 0.06, a1: 0.95, b0: 0.04, b1: 0.98, d0: 0.06, d1: 0.9, min_sites: 3 };
// Tuned: per-check rates as measured by calibration (site/lib/tune.js), cap at the plan's 3-site minimum.
export const TUNED = { ...PLAN, weighted: true, a0: 0.127, a1: 0.669, b0: 0.079, b1: 0.755, d0: 0.146, d1: 0.487, min_sites: 3 };
export const METHODS = { plan: PLAN, tuned: TUNED };

export class Baseline {
  sites = new Map();
  learn(o) {
    let s = this.sites.get(o.site);
    if (!s) this.sites.set(o.site, (s = { ja4s: new Set(), keys: new Set(), ttl: -1 }));
    if (o.ja4s) s.ja4s.add(o.ja4s);
    if (o.key) s.keys.add(o.key);
    if (s.ttl < 0) s.ttl = o.ttl;
  }
  check(o, ttlDelta) {
    const s = this.sites.get(o.site);
    if (!s) return { known: false, a: false, b: false, d: false, b_seen: false, d_seen: false };
    const b_seen = !!o.key && s.keys.size > 0;  // TLS 1.3 hides the key: no evidence either way
    const d_seen = s.ttl >= 0 && o.ttl >= 0;
    return { known: true, a: !s.ja4s.has(o.ja4s), b: b_seen && !s.keys.has(o.key), d: d_seen && Math.abs(o.ttl - s.ttl) > ttlDelta,
      b_seen, d_seen };
  }
}

const term = (fail, p0, p1) => (fail ? Math.log(p1 / p0) : Math.log((1 - p1) / (1 - p0)));

export class Trw {
  constructor(p) { this.p = p; this.tests = new Map(); }
  upper() { return Math.log(this.p.beta / this.p.alpha); }
  lower() { return Math.log((1 - this.p.beta) / (1 - this.p.alpha)); }
  mismatchStep() { return Math.log((1 - this.p.theta1) / (1 - this.p.theta0)); }
  matchStep() { return Math.log(this.p.theta1 / this.p.theta0); }
  siteCap() { return this.upper() / (this.p.min_sites - 0.5); }
  siteLlr(e) {
    let s = term(e.a, this.p.a0, this.p.a1);
    if (e.b_seen) s += term(e.b, this.p.b0, this.p.b1);
    if (e.d_seen) s += term(e.d, this.p.d0, this.p.d1);
    return Math.min(this.siteCap(), Math.max(-this.siteCap(), s));
  }
  // One site's step for this method: weighted per-check sum, or the plan's single +-step.
  step(c) { return this.p.weighted ? this.siteLlr(c) : c.a || c.b || c.d ? this.mismatchStep() : this.matchStep(); }
  observe(client, site, delta) {
    let t = this.tests.get(client);
    if (!t) this.tests.set(client, (t = { score: 0, sites: new Set() }));
    const counted = !t.sites.has(site);
    if (counted) t.sites.add(site);
    const d = counted ? delta : 0;
    t.score += d;
    const s = { counted, delta: d, score: t.score, sites: t.sites.size, decision: 'pending' };
    if (s.score >= this.upper()) s.decision = 'alert';
    else if (s.score <= this.lower()) s.decision = 'clear';
    if (s.decision !== 'pending') this.tests.delete(client);
    return s;
  }
  score(client) { return this.tests.get(client)?.score ?? 0; }
  sitesIn(client) { return this.tests.get(client)?.sites.size ?? 0; }
  expectedN(h1) {  // paper eq. (14)
    const { theta0: t0, theta1: t1, alpha: a, beta: b } = this.p;
    const th = h1 ? t1 : t0;
    const num = h1 ? b * this.upper() + (1 - b) * this.lower() : (1 - a) * this.lower() + a * this.upper();
    return num / (th * this.matchStep() + (1 - th) * this.mismatchStep());
  }
  params() {
    return { ...this.p, upper: this.upper(), lower: this.lower(), mismatch_step: this.mismatchStep(), match_step: this.matchStep(),
      site_cap: this.siteCap() };
  }
}

// Same loop as run() in src/sensor.cpp, without the log.
export function runEvents(obs, baseline, p) {
  const trw = new Trw(p);
  return obs.map((o, i) => {
    const checks = baseline.check(o, p.ttl_delta);
    if (!checks.known) return { i: i + 1, ...o, checks, result: 'unknown', delta: 0, score: trw.score(o.client), sites: 0, decision: 'pending' };
    const s = trw.observe(o.client, o.site, trw.step(checks));
    const mismatch = checks.a || checks.b || checks.d;
    return { i: i + 1, ...o, checks, result: !s.counted ? 'repeat' : mismatch ? 'mismatch' : 'match', ...s };
  });
}

// Hash-chained log, same record layout and hash as src/chainlog.cpp: BLAKE2b-256 over "prev\tseq\tpayload".
// test/parity.mjs writes a chain from this code and checks it with the C++ `zerohour verify`.
const ZERO = '0'.repeat(64);
export const hash = (prev, seq, payload) => blake2bHex(`${prev}\t${seq}\t${payload}`, null, 32);
export class Chain {
  records = [];
  append(payload) {
    const prev = this.records.at(-1)?.hash ?? ZERO, seq = this.records.length + 1;
    const p = payload.replace(/[\t\n]/g, ' ');
    const r = { seq, prev, payload: p, hash: hash(prev, seq, p) };
    this.records.push(r);
    return r;
  }
  line(r) { return `${r.seq}\t${r.prev}\t${r.payload}\t${r.hash}\n`; }
}

// Checks a run of consecutive records, anchored on the first record's prev hash (ZERO when it is record 1).
// Returns one result per record: does the stored link match, and does the BLAKE2b-256 hash match.
export function verifyChain(records) {
  const rows = [];
  let last = records[0]?.seq === 1 ? ZERO : records[0]?.prev, bad = 0;
  for (const [i, r] of records.entries()) {
    const t0 = process.hrtime.bigint();
    const linked = typeof r.payload === 'string' && r.seq === records[0].seq + i && r.prev === last;
    const computed = linked ? hash(r.prev, r.seq, r.payload) : '';
    const ok = linked && computed === r.hash;
    rows.push({ seq: r.seq, ok, reason: ok ? '' : linked ? 'hash mismatch' : 'broken chain', computed, stored: r.hash,
      us: Number(process.hrtime.bigint() - t0) / 1000 });
    if (!ok && !bad) bad = r.seq;
    last = r.hash;
  }
  return { ok: !bad, records: records.length, bad_record: bad, reason: rows.find(x => !x.ok)?.reason ?? '', algorithm: 'BLAKE2b-256', rows };
}

export const percentile = (v, q) => {
  if (!v.length) return 0;
  const s = [...v].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(q * s.length))];
};
