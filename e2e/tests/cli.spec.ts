import { test, expect } from '@playwright/test';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The plan's two gates, run against the real binary and the lab PCAPs.
const bin = join(__dirname, '../../build/zerohour');
const pcap = (n: string) => join(__dirname, '../../lab/pcaps', `${n}.pcap`);
const conf = join(__dirname, '../../zerohour.conf');
const zh = (...args: string[]) => spawnSync(bin, args, { encoding: 'utf8' });

test('G1: the parser prints site, JA4 and JA4S for each handshake', () => {
  const r = zh('show', pcap('learn'));
  expect(r.status).toBe(0);
  const lines = r.stdout.trim().split('\n').slice(1);
  expect(lines).toHaveLength(8);
  for (const [i, l] of lines.entries()) {
    const [site, tls, ja4, ja4s] = l.trim().split(/\s+/);
    expect(site).toBe(`site${i + 1}.lab`);
    expect(tls).toBe('1.2');
    expect(ja4).toMatch(/^t12d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$/);  // client offers TLS 1.2, SNI, ALPN h2
    expect(ja4s).toMatch(/^t12\d{2}(h2|h1|00)_[0-9a-f]{4}_[0-9a-f]{12}$/);
  }
});

test('G2: alert on the attack PCAP, no alert on the normal PCAP', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zh-g2-'));
  const b = join(dir, 'baseline.tsv'), log = join(dir, 'alerts.log');
  expect(zh('learn', pcap('learn'), '-b', b).status).toBe(0);

  const normal = zh('run', pcap('normal'), '-b', b, '-c', conf, '-l', log);
  expect(normal.status).toBe(0);
  expect(normal.stdout).not.toContain('ALERT');
  expect(normal.stdout).toContain('CLEAR  client 10.0.0.23 after 4 sites');

  const attack = zh('run', pcap('attack'), '-b', b, '-c', conf, '-l', log);
  expect(attack.stdout).toContain('ALERT  client 10.0.0.23: interceptor on path after 3 sites (score +6.24)');

  const events = JSON.parse(execFileSync(bin, ['run', pcap('attack'), '-b', b, '-c', conf, '-l', '', '--json'], { encoding: 'utf8' }));
  expect(events[0].checks).toEqual({ A: true, B: true, D: true });

  // tamper with the hash-chained log: verify must fail at the edited record
  expect(zh('verify', log).status).toBe(0);
  const lines = readFileSync(log, 'utf8').split('\n');
  lines[1] = lines[1].replace('"type":"', '"type":"x');
  writeFileSync(log, lines.join('\n'));
  const v = zh('verify', log);
  expect(v.status).toBe(1);
  expect(v.stdout).toContain('FAILED at record 2');
});
