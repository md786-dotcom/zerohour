// Monte Carlo of whole TRW tests: how often each method ends a test with an alert when there is no interceptor
// (false alerts) and when there is one (detection). Both methods see the same random sites (same seed).
import { Trw, PLAN, TUNED } from './engine.js';

// Per-site change rates on a revisit. Nominal = the tuned config's a0/b0/d0 plus provider migrations that change
// every check at once (the plan's "many sites on one provider" limit). Stressed = twice the rates, 3x migrations.
export const MODELS = {
  nominal: { a: 0.06, b: 0.04, d: 0.06, migrate: 0.01, tls13: 0.7 },
  stressed: { a: 0.12, b: 0.08, d: 0.12, migrate: 0.03, tls13: 0.7 },
  attack: { a: 0.95, b: 0.98, d: 0.9, migrate: 0, tls13: 0.5 },  // interceptor on every site; half its sessions TLS 1.3
  // Trade-off case: an interceptor that copies each server's JA4S and sits at the same hop count, so only the
  // forged certificate (B) gives it away. One failed check is what the tuned method treats as benign.
  mimic: { a: 0.06, b: 0.98, d: 0.06, migrate: 0, tls13: 0 },
};
const MAX_SITES = 200;

export function rng(seed) {  // mulberry32
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function site(r, m) {
  const b_seen = r() >= m.tls13;
  if (r() < m.migrate) return { a: true, b: b_seen, d: true, b_seen, d_seen: true };
  return { a: r() < m.a, b: b_seen && r() < m.b, d: r() < m.d, b_seen, d_seen: true };
}

const wilson = (x, n) => {
  const z = 1.96, z2 = z * z, mid = (x + z2 / 2) / (n + z2), half = (z * Math.sqrt((x * (n - x)) / n + z2 / 4)) / (n + z2);
  return [Math.max(0, mid - half), Math.min(1, mid + half)];
};

export function simulate({ trials = 100000, seed = 2026 } = {}) {
  const t0 = performance.now(), results = {};
  for (const [name, p] of [['plan', PLAN], ['tuned', TUNED]]) {
    results[name] = {};
    for (const [scen, m] of Object.entries(MODELS)) {
      const r = rng(seed), trw = new Trw(p);
      let alert = 0, clear = 0, sites = 0;
      for (let i = 0; i < trials; i++) {
        let s;
        for (let k = 0; k < MAX_SITES; k++) {
          s = trw.observe('c', k, trw.step(site(r, m)));
          if (s.decision !== 'pending') break;
        }
        trw.tests.delete('c');  // a test still pending after MAX_SITES ends without a decision
        if (s.decision === 'alert') alert++;
        else if (s.decision === 'clear') clear++;
        sites += s.sites;
      }
      results[name][scen] = { alert_rate: alert / trials, alert_ci: wilson(alert, trials), clear_rate: clear / trials,
        pending_rate: (trials - alert - clear) / trials, mean_sites: sites / trials, alerts: alert };
    }
  }
  return { trials, seed, models: MODELS, results, cases: cases(), elapsed_ms: performance.now() - t0 };
}

// One site's step under each method, for typical benign changes and for an interceptor.
export function cases() {
  const plan = new Trw(PLAN), tuned = new Trw(TUNED), ev = (a, b, d, b_seen = true) => ({ a, b, d, b_seen, d_seen: true });
  return [
    ['Nothing changed', 'benign', ev(false, false, false)],
    ['Certificate renewed (B)', 'benign', ev(false, true, false)],
    ['New server software (A)', 'benign', ev(true, false, false)],
    ['Route change (D)', 'benign', ev(false, false, true)],
    ['CDN node change, TLS 1.3 (A + D)', 'benign', ev(true, false, true, false)],
    ['Provider migration (A + B + D)', 'benign', ev(true, true, true)],
    ['Interceptor, TLS 1.2 (A + B + D)', 'attack', ev(true, true, true)],
    ['Interceptor, TLS 1.3 (A + D)', 'attack', ev(true, false, true, false)],
  ].map(([name, kind, e]) => ({ name, kind, checks: e, plan: plan.step(e), tuned: tuned.step(e) }));
}
