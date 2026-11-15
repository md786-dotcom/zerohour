# zerohour — finds a TLS interceptor without decrypting traffic

Prototype (about 50%) of the Zero Hour Track 2 sensor. It reads only TLS handshakes from a PCAP and fingerprints them
(JA4, JA4S, certificate key, TTL). It compares each site with a learned baseline and decides per client with the
**Threshold Random Walk** of Jung et al. 2004 (`portscan-oak04.pdf`).

| Idea from the paper | In this sensor | Code |
|---|---|---|
| Sequential hypothesis testing | H0 no interceptor / H1 interceptor; after each new site: accept H0, accept H1, or wait | `src/trw.cpp` |
| Random walk | per-client score; mismatch `+ln(0.8/0.1)=+2.08`, match `ln(0.2/0.9)=-1.50`; each site counted once per test | `src/trw.cpp` |
| Thresholds | `ln(β/α)=+4.60` → alert, `ln((1-β)/(1-α))=-4.60` → clear; new test after each decision; E[N] from eq. 14 | `src/trw.cpp`, `zerohour.conf` |

Pipeline: libpcap → TCP reassembly (first 64 KB per direction) → TLS parser → JA4/JA4S (OpenSSL SHA-256), key hash
(OpenSSL X.509) → checks **A** JA4S new, **B** cert key new, **D** TTL moved > 2 → TRW → hash-chained log (libsodium BLAKE2b).

## Build and run

```sh
brew install cmake libsodium googletest          # OpenSSL 3 and libpcap already present on macOS
cmake -S . -B build && cmake --build build -j
cmake --build build --target pcaps               # lab: real TLS 1.2 handshakes via OpenSSL memory BIOs -> lab/pcaps/*.pcap

./build/zerohour show  lab/pcaps/learn.pcap      # gate G1: site, JA4, JA4S, key, TTL per handshake
./build/zerohour learn lab/pcaps/learn.pcap      # baseline.tsv
./build/zerohour run   lab/pcaps/attack.pcap     # ALERT after 3 sites (+6.24); also normal / onechange
./build/zerohour verify alerts.log               # hash chain check
./build/zerohour serve                           # dashboard at http://127.0.0.1:8765/
```

## Calibrate θ0/θ1 (Phase 3)

`calibrate` learns a baseline from one capture, then measures θ0 = match rate of a later clean revisit and
θ1 = match rate under an interceptor (Laplace estimate (matches+1)/(sites+2), with the 95% range of the raw rate).
It prints the steps, how many mismatches in a row alert, and the two lines for `zerohour.conf`.

```sh
sh lab/capture.sh real-learn.pcap                # sudo tcpdump; browse 20+ sites, Ctrl-C
sh lab/capture.sh real-revisit.pcap              # a day later, same network, same sites
./build/zerohour calibrate real-learn.pcap real-revisit.pcap lab/pcaps/attack.pcap
demo3/demo3.sh                                   # 3 benign changes: calibrate into demo3/zerohour.conf, rerun
```

## Constraints: runtime < 4 ms, fewer false alerts

| | Before (`zerohour.conf`, plan) | After (`zerohour.tuned.conf`) |
|---|---|---|
| Step per site | any check failed `+2.08`, else `−1.50` | sum of per-check LLRs (rates from calibration), capped at `±4.60/2.5` |
| Evidence log | every record fully flushed (`F_FULLFSYNC` / `fdatasync`) | records ordered (`F_BARRIERFSYNC`), alerts fully flushed |
| p99 per handshake, `busy.pcap` (8 clients, 64 handshakes) | 4.33 ms (over 4 ms) | 3.22 ms |
| p99 per handshake, `attack.pcap` (every site an alert or notice) | 4.88 ms | 4.57 ms (still over: each alert waits for a full flush) |
| False alerts, simulated (85% TLS 1.3, 25% of sites bypass the interceptor) | 7.8% of tests | 0.16% |
| Detection, simulated | 99.5%, 4.3 sites | 98.4%, 6.5 sites |
| False alerts, real `busy.pcap` (6 clean clients) | 0 | 0 |

```sh
./build/zerohour bench lab/pcaps/learn.pcap lab/pcaps/busy.pcap -c zerohour.tuned.conf   # PASS/FAIL vs 4 ms
./build/zerohour run lab/pcaps/multichange.pcap -c zerohour.tuned.conf                   # 3 benign changes: clear
```

Trade-off: an interceptor that copies each server's JA4S and hop count fails only check B; the tuned method treats
one failed check as weak evidence and detects it far less often. The site's `/tuning` page shows how the weights and
the cap were chosen; `/compare` shows both constraints.

## Web console (Vercel)

`site/` is the deployed demo: static pages plus Vercel functions in `site/api/`. The engine (`site/lib/engine.js`)
is a port of `src/trw.cpp` and is checked against the C++ sensor by `node site/test/parity.mjs`. The console's
live replay reads `lab/pcaps/busy.pcap` (real lab handshakes, 8 clients, 2 intercepted); the false-alert
simulation is `site/lib/sim.js` and the tuning sweep `site/lib/tune.js`.
Regenerate fixtures with `sh site/scripts/fixtures.sh`; deploy with `cd site && vercel deploy --prod`.

**Live capture** (`/#capture`, `site/api/capture.js`): the user types 3 to 8 public hosts or IPv4 addresses. A Vercel Sandbox VM
starts from a snapshot (tcpdump, mitmproxy, this sensor built on Linux) and runs `site/lib/capture.sh`. A client in its own
network namespace visits each host two times, and tcpdump records the client's side of the link. The second visit goes
direct or through `mitmdump --mode transparent` on the client's gateway. `zerohour show` parses both PCAPs and the
engine decides (baseline from the first visit). Both PCAPs can be downloaded. Private, loopback and link-local addresses are refused.
Rebuild the snapshot after a sensor change: `cd site && node --env-file=../.env.local scripts/snapshot.mjs <pushed commit>`.

## Tests

```sh
(cd build && ctest)                              # GoogleTest, written test-first: trw, chainlog, tls (37 tests)
sh tests/calibrate_e2e.sh                        # E2E: calibrate on the lab PCAPs -> e2e/artifacts/calibrate.txt
sh tests/wireshark_check.sh                      # tshark vs sensor: JA4, SNI, TTL, issuer vs verdict -> e2e/artifacts/wireshark.txt
node site/test/parity.mjs                        # web engine == C++ sensor on every lab event
(cd e2e && npx playwright test -c site.config.ts) # E2E of the deployed site -> e2e/artifacts/site-*.png
cd e2e && npm install && npx playwright test     # E2E: plan gates G1/G2 + the 5 demo steps in the dashboard
npx playwright show-report artifacts/report      # artifact: HTML report with trace + video per test
```

Debug with sanitizers: `cmake -S . -B build-asan -DZH_ASAN=ON`.

## Not in this prototype yet

Check C (TLS 1.3 answer size), live capture from an interface, IPv6, QUIC/ECH, signing the log head, AFL++ fuzz runs,
Docker + mitmproxy lab (θ1 from a real interceptor; today θ1 comes from the lab attack PCAP). See the plan's Phase 3.
