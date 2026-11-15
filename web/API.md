# zerohour serve — HTTP API

`zerohour serve --port 8765` binds 127.0.0.1 only. All API responses are `application/json`.
Scenario names are a fixed whitelist: `learn`, `normal`, `onechange`, `multichange`, `attack` (files `<pcaps>/<name>.pcap`).

| Method + path | Does | Response |
|---|---|---|
| `GET /` | dashboard (`web/index.html`) | HTML |
| `GET /api/state` | current state | `{"baseline_sites": 8, "log_records": 3, "params": Params}` |
| `POST /api/reset` | delete baseline + log | `{"ok": true}` |
| `POST /api/learn` | learn baseline from `learn.pcap` (replaces old baseline) | `{"sites": [SiteRow...]}` |
| `POST /api/run?scenario=normal` | fresh TRW test over the scenario PCAP, appends notices/decisions to the log | `RunResult` |
| `POST /api/tamper` | rewrites the payload of log record 1 (demo of a tampered log) | `{"ok": true, "record": 1}` or `{"ok": false, "error": "..."}` |
| `POST /api/verify` | verify the hash chain | `{"ok": false, "records": 5, "bad_record": 1, "reason": "hash mismatch"}` |

Errors: HTTP 400/404 with `{"error": "..."}` (e.g. run before learn → 400 `{"error":"no baseline, run learn first"}`).

```
Params    = {"theta0":0.9,"theta1":0.2,"alpha":0.01,"beta":0.99,"ttl_delta":2,
             "upper":4.595,"lower":-4.595,"mismatch_step":2.079,"match_step":-1.504,
             "expected_n_h0":3.93,"expected_n_h1":3.30}
SiteRow   = {"site":"site1.lab","ja4s":["t120400_c02f_..."],"keys":["3fa1..."],"ttl":52}
RunResult = {"scenario":"attack","params":Params,"events":[Event...],
             "decisions":[{"client":"10.0.0.23","decision":"alert","sites":3,"score":6.238}],
             "log_records":7}
Event     = {"i":1,"ts":1700000000.0,"client":"10.0.0.23","server":"93.184.216.11","site":"site1.lab",
             "tls":"1.2","ja4":"t12d...","ja4s":"t120400_...","key":"3fa1...","ttl":64,
             "baseline":{"ja4s":["..."],"keys":["..."],"ttl":52} | null,
             "checks":{"A":true,"B":true,"D":true},          // true = check FAILED (changed)
             "result":"mismatch",                             // match | mismatch | unknown | repeat
             "delta":2.079,"score":2.079,"sites":1,"decision":"pending"}  // pending | alert | clear
```

Log record payloads are JSON objects:
`{"type":"notice","client":"10.0.0.23","site":"site3.lab","score":2.079}` and
`{"type":"alert"|"clear","client":"10.0.0.23","sites":3,"score":6.238}`.

## Dashboard test hooks (contract with e2e/ Playwright tests)

Buttons (each a `<button>` with this `data-testid` and the visible label in quotes):
`step-learn` "Learn", `step-normal` "Normal", `step-onechange` "One change", `step-attack` "Attack",
`step-tamper` "Tamper log", `step-verify` "Verify log", `reset` "Reset".

Read-outs:
- `baseline-count` — number of learned sites, e.g. `8`
- `verdict` — verdict of the latest run: `Alert`, `Clear` or `Pending`
- `verdict-detail` — e.g. `Alert after 3 sites · score +6.24`
- `run-<scenario>` — one card per finished run (normal/onechange/attack) containing its verdict text
- `score-chart` — the SVG score walk (one `<path data-scenario="<scenario>">` per finished run)
- `event-row` — one `<tr>` per event of the latest run; each has `data-result` (match|mismatch|unknown|repeat)
  and `data-score` (2 decimals, e.g. `6.24`)
- `compare-before` / `compare-after` — before/after columns (Normal run vs Attack run); each site row
  is `data-testid="compare-row"` with `data-site` and `data-mismatch="true|false"`
- `verify-result` — `Chain intact · N records` or `Broken at record K`
- `error` — visible error banner text (e.g. running before learning)
