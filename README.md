# vulnarable_lan10

An **intentionally vulnerable** Flask app for testing security scanners and
remediation tooling (SAST, SCA, secret scanning, DAST).

> **Warning:** never deploy this or bind it to a public/shared network. The app
> listens on `127.0.0.1` by default and runs with `debug=True`.

## Run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
python app.py          # http://127.0.0.1:5000
pytest -q              # every test passes while the vulnerability exists
```

## Vulnerabilities

| # | Route / location | Issue | CWE |
|---|------------------|-------|-----|
| 1 | `POST /login` | SQL injection (auth bypass: `admin' --`) | 89 |
| 2 | `GET /search?q=` | SQL injection (UNION dump of hashes) | 89 |
| 3 | `GET /greet?name=` | Reflected XSS | 79 |
| 4 | `/comments` | Stored XSS + server-side template injection | 79, 1336 |
| 5 | `GET /ping?host=` | OS command injection (`shell=True`) | 78 |
| 6 | `GET /download?file=` | Path traversal (`../app.py`) | 22 |
| 7 | `GET /fetch?url=` | SSRF, TLS verification disabled | 918, 295 |
| 8 | `GET /notes/<id>` | IDOR, no auth or ownership check | 639, 862 |
| 9 | `GET /calc?expr=` | `eval()` injection | 95 |
| 10 | `POST /load-session` | Insecure `pickle` deserialization | 502 |
| 11 | `POST /import-config` | Unsafe `yaml.load` | 502 |
| 12 | `GET /redirect?next=` | Open redirect | 601 |
| 13 | `GET /reset-token` | Predictable token (seeded `random`) | 330 |
| 14 | `GET /admin/users` | Access control trusts `X-Admin` header | 285 |
| 15 | `GET /delete-comments` | State change over GET, no CSRF protection | 352 |
| 16 | `app.py` top | Hardcoded secret key, AWS-style keys, DB password | 798 |
| 17 | `init_db()` | Unsalted MD5 password hashes | 327 |
| 18 | `/login` | Verbose errors leak query and DB error | 209 |
| 19 | `app.run(debug=True)` | Werkzeug debug console enabled | 489 |
| 20 | `requirements.txt` | Outdated dependencies with known CVEs | 1104 |

The AWS values are the public AWS documentation examples, not real credentials.
