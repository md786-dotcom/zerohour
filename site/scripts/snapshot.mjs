// One-time setup for live capture: builds a Vercel Sandbox snapshot with tcpdump, mitmproxy and the zerohour sensor
// (built from the public GitHub repo at the given commit), then writes its id to site/lib/snapshot.js.
//   cd site && vercel env pull .env.local    (or run from the repo root, where .env.local has VERCEL_OIDC_TOKEN)
//   node --env-file=../.env.local scripts/snapshot.mjs [commit]
import { writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { Sandbox } from '@vercel/sandbox';

const commit = process.argv[2] || execSync('git rev-parse HEAD').toString().trim();
const sb = await Sandbox.create({ persistent: false, timeout: 900_000, resources: { vcpus: 4 } });
const sh = async cmd => {
  const r = await sb.runCommand({ cmd: 'bash', args: ['-c', cmd], sudo: true });
  const out = (await r.stdout()) + (await r.stderr());
  console.log(`$ ${cmd.split('\n')[0]}  -> ${r.exitCode}`);
  if (r.exitCode !== 0) throw new Error(out.slice(-3000));
  return out;
};
try {
  await sh(`apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump iptables iproute2 git cmake g++ \
    libssl-dev libpcap-dev libsodium-dev libgtest-dev >/dev/null`);
  await sh('python3 -m pip install -q --break-system-packages mitmproxy && mitmdump --version | head -1');
  // mitmproxy makes its CA on first start; do it once so every capture uses the same interceptor CA.
  await sh('mkdir -p /opt/mitm && (timeout 6 mitmdump --set confdir=/opt/mitm -q || true) && ls /opt/mitm/mitmproxy-ca-cert.pem');
  await sh(`git clone -q https://github.com/md786-dotcom/zerohour /opt/zerohour && cd /opt/zerohour && git checkout -q ${commit}
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build --target zerohour -j4 >/dev/null
    install build/zerohour /usr/local/bin/zerohour && zerohour show lab/pcaps/attack.pcap --json | head -c 200`);
  const snap = await sb.snapshot({ expiration: 0 });
  writeFileSync(new URL('../lib/snapshot.js', import.meta.url),
    `// Written by site/scripts/snapshot.mjs. Sandbox snapshot with tcpdump, mitmproxy and zerohour at ${commit.slice(0, 7)}.\n` +
    `export const SNAPSHOT = ${JSON.stringify({ id: snap.snapshotId, commit })};\n`);
  console.log('snapshot', snap.snapshotId);
} catch (e) {
  await sb.stop();
  throw e;
}
