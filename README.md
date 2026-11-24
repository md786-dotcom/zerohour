# zerohour

zerohour finds a TLS interceptor between a client and the internet. It does not decrypt the traffic.

Demo: https://zerohour-pi.vercel.app

zerohour is a sensor for Zero Hour Track 2. It reads only the TLS handshakes in a PCAP file. For each handshake, it
records four fingerprints: JA4, JA4S, the certificate key and the TTL. It compares each site with a baseline that it
learned before. For each client, it makes a decision with the **Threshold Random Walk** (TRW) of Jung et al. 2004
(`portscan-oak04.pdf`).

| Idea from the paper | In this sensor | Code |
|---|---|---|
| Sequential hypothesis testing | H0: no interceptor. H1: an interceptor. After each new site, the sensor accepts H0, accepts H1 or waits. | `src/trw.cpp` |
| Random walk | Each client has a score. A mismatch adds `ln(0.8/0.1) = +2.08`. A match adds `ln(0.2/0.9) = −1.50`. The sensor counts each site one time in a test. | `src/trw.cpp` |
| Thresholds | At `ln(β/α) = +4.60`, the sensor gives an alert. At `ln((1−β)/(1−α)) = −4.60`, the client is clear. A new test starts after each decision. E[N] comes from eq. 14. | `src/trw.cpp`, `zerohour.conf` |

The data path of the sensor:

1. libpcap reads the packets.
2. TCP reassembly keeps the first 64 KB of each direction.
3. The TLS parser reads the handshake.
4. OpenSSL calculates JA4 and JA4S (SHA-256) and the hash of the key (X.509).
5. Three checks compare the handshake with the baseline:
   - **A**: the JA4S is new.
   - **B**: the certificate key is new.
   - **D**: the TTL changed by more than 2.
6. The TRW adds a step to the score of the client.
7. libsodium writes each record to a hash-chained log (BLAKE2b).

## Build and run

1. Install the dependencies. macOS has OpenSSL 3 and libpcap.

   ```sh
   brew install cmake libsodium googletest
   ```

2. Build the sensor.

   ```sh
   cmake -S . -B build && cmake --build build -j
   ```

3. Make the lab PCAP files. The lab makes real TLS 1.2 handshakes with OpenSSL memory BIOs. It writes them to
   `lab/pcaps/*.pcap`.

   ```sh
   cmake --build build --target pcaps
   ```

4. Run the sensor.

   ```sh
   ./build/zerohour show  lab/pcaps/learn.pcap      # shows site, JA4, JA4S, key and TTL of each handshake
   ./build/zerohour learn lab/pcaps/learn.pcap      # writes baseline.tsv
   ./build/zerohour run   lab/pcaps/attack.pcap     # alert after 3 sites (+6.24); also use normal or onechange
   ./build/zerohour verify alerts.log               # checks the hash chain
   ./build/zerohour serve                           # starts the dashboard at http://127.0.0.1:8765/
   ```

## Calibrate θ0 and θ1

The `calibrate` command learns a baseline from one capture. Then it measures two rates:

- θ0: the match rate of a clean visit at a later time.
- θ1: the match rate through an interceptor.

Each rate is a Laplace estimate: (matches + 1) / (sites + 2). The command also shows the 95% range of the raw rate.
It shows the steps and the number of mismatches in sequence that cause an alert. It also gives the two lines for
`zerohour.conf`.

To calibrate on your network:

1. Record a capture to learn. The script uses `sudo tcpdump`. Go to 20 or more sites. Then push Ctrl-C.

   ```sh
   sh lab/capture.sh real-learn.pcap
   ```

2. Record a second capture one day later. Use the same network and the same sites.

   ```sh
   sh lab/capture.sh real-revisit.pcap
   ```

3. Calibrate.

   ```sh
   ./build/zerohour calibrate real-learn.pcap real-revisit.pcap lab/pcaps/attack.pcap
   ```

For an example, run `demo3/demo3.sh`. In `multichange.pcap`, 4 of 8 sites change in normal ways. The script
calibrates into `demo3/zerohour.conf` and runs the sensor again.

## Constraints: time less than 4 ms, fewer false alerts

| | Before (`zerohour.conf`, plan method) | After (`zerohour.tuned.conf`, tuned method) |
|---|---|---|
| Step for each site | If a check fails: `+2.08`. If no check fails: `−1.50`. | The sum of the log-likelihood ratios (LLR) of the checks. The rates come from calibration. The cap is `±4.60/2.5`. |
| Evidence log | Each record waits for a full flush (`F_FULLFSYNC` / `fdatasync`). | Records use an ordered write (`F_BARRIERFSYNC`). Only alerts wait for a full flush. |
| p99 time for each handshake, `busy.pcap` (8 clients, 64 handshakes) | 4.33 ms (more than 4 ms) | 3.22 ms |
| p99 time for each handshake, `attack.pcap` (each site gives an alert or a notice) | 4.88 ms | 4.57 ms (more than 4 ms, because each alert waits for a full flush) |
| False alerts, simulated (85% TLS 1.3; 25% of sites do not go through the interceptor) | 7.8% of tests | 0.16% of tests |
| Detection, simulated | 99.5%, after 4.3 sites | 98.4%, after 6.5 sites |
| False alerts, real `busy.pcap` (6 clients without an interceptor) | 0 | 0 |

```sh
./build/zerohour bench lab/pcaps/learn.pcap lab/pcaps/busy.pcap -c zerohour.tuned.conf   # PASS or FAIL against 4 ms
./build/zerohour run lab/pcaps/multichange.pcap -c zerohour.tuned.conf                   # 4 normal changes: clear
```

**Trade-off:** An interceptor can copy the JA4S and the hop count of each server. Then only check B fails. The tuned
method gives one failed check a small weight. Thus it finds this interceptor much less frequently.

The `/tuning` page shows how we chose the weights and the cap. The `/compare` page shows the two constraints.

## Web console (Vercel)

The `site/` folder is the demo on Vercel. It has static pages and Vercel functions in `site/api/`.

- The engine `site/lib/engine.js` is a port of `src/trw.cpp`. The test `node site/test/parity.mjs` compares it with
  the C++ sensor.
- The live replay reads `lab/pcaps/busy.pcap`. This file has real lab handshakes from 8 clients. Two clients are
  behind an interceptor.
- `site/lib/sim.js` simulates the false alerts. `site/lib/tune.js` does the tuning sweep.

To make the fixtures again, run `sh site/scripts/fixtures.sh`.

To deploy:

- Each push to `main` deploys to production.
- For a manual deploy, run `vercel deploy --prod` from the repository root. The Root Directory of the Vercel project
  is `site/`.

| Page | Contents |
|---|---|
| `/` Demo | **Live replay** of `busy.pcap` (8 clients, 16 sites each, 2 clients behind an interceptor). It shows the alerts, the false alerts and the p99 detection time. **Lab scenarios** shows the score after each site for the plan method and the tuned method. The scenarios are Normal, One change, Many changes and Attack. **Wireshark** shows the tshark view of `learn.pcap`, `multichange.pcap` and `attack.pcap`. You can download each file. **Evidence log**: your browser calculates the BLAKE2b-256 hash of each record again. "Change one record" breaks the chain. |
| `/live` | Live capture on real sites. Refer to the section below. |
| `/how-live` | The data path of live capture, the tools and their versions, and the changes that we made for live capture. |
| `/tuning` | How we chose the tuned method: measure p₀ and p₁ for each check, give each check a weight, select the cap. |
| `/compare` | The two constraints, before and after: the p99 time less than 4 ms, and the false alerts (simulated and real). |

### Live capture

The `/live` page records real handshakes to sites that you type. It uses only the tuned method. The code is in
`site/api/live.js`, `site/lib/live.js` and `site/lib/capture.sh`.

**Step 1, Learn:**

1. The function starts a Vercel Sandbox VM from a snapshot. The snapshot has tcpdump, mitmproxy and the sensor, built
   on Linux.
2. The VM is the network of the client. The client is in its own network namespace.
3. The client connects to each site one time. tcpdump records the client side of the link.
4. `zerohour show` reads each handshake. These handshakes are the baseline.

Each site keeps one IPv4 address for the full session.

**Step 2, Test:** The client connects to the same sites again, in the same VM. You can do the test many times. Select
a path and a scenario:

| Path | Scenario | Change |
|---|---|---|
| Direct | Normal | No change. |
| Direct | One change | One site gets a new route through 3 more routers. Check D fails. |
| Direct | Many changes | Up to 4 sites get new routes or new TLS settings (`curl --tls-max 1.2`). One site gets the two changes. |
| Through mitmproxy | Attack | All sites go through `mitmdump --mode transparent` on the gateway of the client. |

The page shows each handshake when it arrives: the checks, the step and the score. At +4.60, the page shows Alert. If
a test ends below the threshold, the page shows Clear. The VM keeps a hash-chained evidence log of each test. The page
verifies the log with BLAKE2b-256. You can download `learn.pcap` and each `test-N.pcap`.

The page is public. Thus it has these limits:

- Type 3 to 8 public host names or IPv4 addresses. The function refuses private, loopback, link-local and reserved
  addresses.
- A maximum of 4 VMs can run at the same time.
- A VM does one test at a time.
- A VM stops when you close the page, or after 15 minutes. Each test adds 5 minutes.

After a change to the sensor, make the snapshot again. Use a commit that you pushed:

```sh
cd site && node --env-file=../.env.local scripts/snapshot.mjs <pushed commit>
```

## Tests

```sh
(cd build && ctest)                              # GoogleTest for trw, chainlog and tls (37 tests, written before the code)
sh tests/calibrate_e2e.sh                        # E2E: calibrate with the lab PCAPs; writes e2e/artifacts/calibrate.txt
sh tests/wireshark_check.sh                      # compares tshark and the sensor: JA4, SNI, TTL, issuer and verdict; writes e2e/artifacts/wireshark.txt
node site/test/parity.mjs                        # makes sure that the web engine and the C++ sensor agree on each lab event
(cd e2e && npx playwright test -c site.config.ts) # E2E of the deployed site, with /live on real traffic; writes to e2e/artifacts/
cd e2e && npm install && npx playwright test     # E2E of the CLI and the 5 demo steps in the dashboard
npx playwright show-report artifacts/report      # opens the HTML report, with a trace and a video for each test
```

To debug with sanitizers, build with `cmake -S . -B build-asan -DZH_ASAN=ON`.
