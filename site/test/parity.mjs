// The web backend's engine must decide exactly like the C++ sensor. For each lab scenario and both methods,
// compares every event (result, step, score, decision) of site/lib/engine.js with `zerohour run --json`.
// Run from the repo root after `cmake --build build`: node site/test/parity.mjs
import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Baseline, runEvents, PLAN, TUNED } from '../lib/engine.js';
import { LAB } from '../lib/lab.js';

const dir = mkdtempSync(join(tmpdir(), 'zh-parity-'));
const zh = (...a) => execFileSync('./build/zerohour', a, { encoding: 'utf8' });
zh('learn', 'lab/pcaps/learn.pcap', '-b', join(dir, 'b.tsv'));
const base = new Baseline();
LAB.learn.forEach(o => base.learn(o));

let fail = 0, n = 0;
for (const [conf, p] of [['zerohour.conf', PLAN], ['zerohour.tuned.conf', TUNED]])
  for (const s of ['normal', 'onechange', 'multichange', 'attack']) {
    const cpp = JSON.parse(zh('run', `lab/pcaps/${s}.pcap`, '-b', join(dir, 'b.tsv'), '-c', conf, '-l', join(dir, 'l.log'), '--json'));
    const js = runEvents(LAB[s], base, p);
    const bad = cpp.findIndex((c, i) => { const j = js[i]; n++;
      return !j || c.result !== j.result || c.decision !== j.decision || Math.abs(c.delta - j.delta) > 1e-4 || Math.abs(c.score - j.score) > 1e-4; });
    const ok = bad < 0 && cpp.length === js.length;
    if (!ok) fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${conf.padEnd(20)} ${s.padEnd(12)} ${cpp.length} events${ok ? '' : ` first difference at event ${bad + 1}`}`);
  }
console.log(`${n} events compared`);
process.exit(fail ? 1 : 0);
