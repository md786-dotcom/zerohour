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
| Step per site | one Bernoulli trial: any check failed `+2.08`, else `−1.50` | sum of per-check LLRs (A, B, D each with its own p0/p1), capped at `±4.60/2.5` |
| False alerts, simulated normal traffic | 1.1% of tests | ~0 (none in 100k) |
| Worst case per handshake (attack capture) | 2.29 ms | 1.12 ms (log file kept open) |

```sh
./build/zerohour bench lab/pcaps/learn.pcap lab/pcaps/attack.pcap -c zerohour.tuned.conf   # PASS/FAIL vs 4 ms
./build/zerohour run lab/pcaps/multichange.pcap -c zerohour.tuned.conf                     # 3 benign changes: clear
```

Trade-off: an interceptor that copies each server's JA4S and hop count fails only check B, and the tuned method
treats one failed check as normal (the plan method catches it). See `/compare` on the site.

## Web console (Vercel)

`site/` is the deployed demo: static pages plus Vercel functions in `site/api/`. The engine (`site/lib/engine.js`)
is a port of `src/trw.cpp` and is checked against the C++ sensor by `node site/test/parity.mjs`. The console's
traffic is simulated (`site/lib/live.js`); the lab replay and packet evidence come from `lab/pcaps`.
Regenerate fixtures with `sh site/scripts/fixtures.sh`; deploy with `cd site && vercel deploy --prod`.

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
