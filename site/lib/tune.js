// How the tuned method was fitted (the "How we tuned it" page). Every number here is computed, nothing is typed in.
import { PLAN, Trw } from './engine.js';
import { MODELS, runTests } from './sim.js';

// Step 1, measure: per-check failure rates that `zerohour calibrate` reads from a clean revisit (p0) and from an
// attack capture (p1). Here they follow from the traffic model: migrations fail every check, bypassed sites look clean.
export function measured() {
  const N = MODELS.nominal, A = MODELS.attack, r3 = x => Math.round(x * 1000) / 1000;
  const p0 = k => N.migrate + (1 - N.migrate) * N[k], p1 = k => (1 - A.bypass) * A[k] + A.bypass * p0(k);
  return Object.fromEntries(['a', 'b', 'd'].map(k => [k, { p0: r3(p0(k)), p1: r3(p1(k)) }]));
}

// Step 2, weigh: each check's log-likelihood ratio when it fails and when it holds.
export function weights(m = measured()) {
  return Object.fromEntries(Object.entries(m).map(([k, { p0, p1 }]) => [k, { fail: Math.log(p1 / p0), hold: Math.log((1 - p1) / (1 - p0)) }]));
}

export const tunedParams = (min_sites, m = measured()) =>
  ({ ...PLAN, weighted: true, a0: m.a.p0, a1: m.a.p1, b0: m.b.p0, b1: m.b.p1, d0: m.d.p0, d1: m.d.p1, min_sites });

// Step 3, cap: sweep the per-site cap (as "fewest sites that can decide"). We keep 3, the plan's own minimum for an
// alert ("3 mismatches in a row give an alert"); the sweep shows what a smaller or larger cap would trade.
export const CAPS = [1, 2, 2.5, 3, 3.5, 4, 5];
export function sweep({ trials = 40000, seed = 7 } = {}) {
  const rows = CAPS.map(min_sites => {
    const p = tunedParams(min_sites), fp = runTests(p, MODELS.nominal, trials, seed), det = runTests(p, MODELS.attack, trials, seed);
    return { min_sites, cap: new Trw(p).siteCap(), false_alert: fp.alert_rate, false_ci: fp.alert_ci, detection: det.alert_rate,
      sites_to_alert: det.mean_sites };
  });
  const chosen = 3;
  const plan = { false_alert: runTests(PLAN, MODELS.nominal, trials, seed).alert_rate, detection: runTests(PLAN, MODELS.attack, trials, seed).alert_rate };
  plan.sites_to_alert = runTests(PLAN, MODELS.attack, trials, seed).mean_sites;
  return { trials, seed, rule: "3 sites, the plan's own minimum for an alert", rows, chosen, plan };
}
