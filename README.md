# LaravelMail Email Validation v2

This repository is a standalone Laravel application ported from the supplied Streamlit email toolkit. All environment keys use the `V2_` prefix.

## Streamlit-to-HTTP mapping

The attached `app.py` has no HTTP routes. Its six UI workflows map to these JSON/multipart routes while retaining the underlying rules and result fields:

| Streamlit workflow | Laravel v2 route |
|---|---|
| Email Validator | `POST /api/v2/validate` |
| Multi-email validator | `POST /api/v2/validate/batch` |
| Batch CSV and Gmail Batch | `POST /api/v2/validate/csv` (`gmail_only`) |
| Provider Email Extractor | `POST /api/v2/extract/provider-emails` |
| Send Test Email (yagmail) | `POST /api/v2/send-test-email` (Laravel Mail) |
| Email Permutator and Validator | `POST /api/v2/permutations` (`validate`) |

There was no authentication or authorization check in `app.py`; v2 deliberately leaves these routes unauthenticated to preserve that behavior. Production deployments should put an authenticated gateway in front if exposure is not intended.

## Setup

```bash
cp .env.v2.example .env.v2
composer install
set -a; . ./.env.v2; set +a
php artisan key:generate --show # copy output into V2_APP_KEY
php artisan serve --port=8080
```

The bootstrap loads `.env.v2` directly and never reads or reuses the source app env names. In production, the same `V2_` keys can be injected by the process manager.

## API examples

```bash
curl -sS -X POST http://localhost:8080/api/v2/validate \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","enable_company_lookup":true}'

curl -sS -X POST http://localhost:8080/api/v2/validate/batch \
  -H 'Content-Type: application/json' \
  -d '{"emails":["user@example.com","info@example.com"]}'

curl -sS -X POST http://localhost:8080/api/v2/validate/csv \
  -F 'files[]=@leads.csv' -F 'email_column=email' -F 'gmail_only=0'

curl -sS -X POST http://localhost:8080/api/v2/extract/provider-emails \
  -F 'files[]=@leads.csv' -F 'providers[]=gmail' -F 'providers[]=microsoft_365'

curl -sS -X POST http://localhost:8080/api/v2/permutations \
  -H 'Content-Type: application/json' \
  -d '{"first_name":"John","last_name":"Doe","nickname":"Johnny","domain":"example.com","validate":false}'

curl -sS -X POST http://localhost:8080/api/v2/send-test-email \
  -H 'Content-Type: application/json' \
  -d '{"sender_email":"me@gmail.com","sender_password":"app-password","recipient_email":"test@example.com","subject":"Test","body":"Hello","smtp_host":"smtp.gmail.com","smtp_port":587}'
```

Responses are always JSON. Success uses `{"ok":true,"data":...}`. Errors use `{"ok":false,"error":{"code":...,"message":...,"details":...}}`.

## Behavior and operations

- MX/provider lookups, SMTP RCPT response codes, catch-all probes, WHOIS age/organisation, disposable and role address classification, original verdict labels, and the original score penalties are preserved.
- DNS/WHOIS/catch-all lookups are cached. SMTP probes keep the source app's randomized delay and response-code handling.
- CSV decoding detects UTF-8, UTF-16, Windows-1252, then falls back to ISO-8859-1.
- Sending is encapsulated in a queueable Laravel job and uses an isolated per-request Laravel Mail transport. Port 465 uses SMTPS; other ports use SMTP/STARTTLS behavior.
- The source's Stop buttons and four-hour UI refresh were Streamlit session concerns. HTTP clients cancel requests normally, while production queue workers provide durable background execution.
- File uploads are read from Laravel's temporary upload storage and are not retained. Dedicated `storage/app/v2/imports` and `exports` paths are reserved for future queued exports.

## Test and build

```bash
composer test
docker build -t validation-laravel-v2 .
```

## Scheduling and queues

The Streamlit source had no cron-triggered business task. Laravel's scheduler is therefore intentionally empty rather than inventing behavior. The test-email action is a queueable job but is dispatched synchronously to preserve the source UI's immediate success/error response. It can be changed to `dispatch()` without changing the job when asynchronous sending is wanted.

## Streamlit Cloud UI

The repository also includes `streamlit_app.py`, the entry point Streamlit Community Cloud expects. It preserves the supplied Streamlit app as a standalone UI: validation, CSV/Gmail batches, provider extraction, permutations, SMTP checks, WHOIS/domain age, catch-all checks, scoring and test sending all run inside the Streamlit process.

This is intentionally not a thin client for the Laravel API. The supplied UI includes long-running batch progress, stop controls, uploads and SMTP sender settings that are stateful in the Streamlit session, while the Laravel API is a separate deployable interface. Keeping the UI standalone preserves the original behavior and lets Streamlit Cloud run it without requiring a second deployment.

### Deploy

1. In Streamlit Community Cloud, select `laravelmail/cleaning.laravelmail.com`.
2. Set the branch to `main` after this change is merged.
3. Set the entry point to `streamlit_app.py`.
4. Deploy. Streamlit installs `requirements.txt` and uses the Python version in `runtime.txt`.

Local run:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
streamlit run streamlit_app.py
```

No secret is committed. SMTP credentials are entered at runtime in the Streamlit UI. Streamlit Cloud does not need Laravel's `.env.v2` to run this standalone UI.

### Docker and Make

```bash
make streamlit-up       # builds and starts http://localhost:8501
make streamlit-logs     # follow startup/runtime logs
make streamlit-down     # stop it
```

Or without Docker: `make install && make streamlit`.

The Streamlit image is isolated in `Dockerfile.streamlit`; the existing `Dockerfile` remains the Laravel API image. `STREAMLIT_MAX_CONCURRENT` defaults to 8 and is capped at 32.

### Streamlit Cloud hang fix

The imported app used 300 concurrent DNS/WHOIS/SMTP workers, performed WHOIS by default, started duplicate catch-all probes for the same domain, and installed a forced autorefresh. On constrained Streamlit Cloud instances, that combination can exhaust threads/sockets and make a run appear frozen. The app now:

- uses 8 workers by default instead of 300 (configurable with `STREAMLIT_MAX_CONCURRENT`)
- disables slow WHOIS/company/domain-age lookups by default while keeping them available as an option
- serializes catch-all detection per domain so a Gmail batch does not open the same probe hundreds of times
- removes the forced rerun timer and lets Streamlit Cloud manage app sleep/wake

Direct SMTP validation still needs outbound TCP port 25. Some hosted platforms block it; those checks then return invalid/unknown after their bounded timeout rather than hanging the app indefinitely.

### Streamlit Community Cloud execution modes

The default is now **Fast cloud-safe mode**. It performs syntax, disposable/role, MX and provider checks without opening direct SMTP port-25 connections. Enable "Deep SMTP mailbox + catch-all checks" only on infrastructure where outbound port 25 is confirmed. Streamlit Community Cloud commonly restricts that port, which can otherwise make every address wait on two network timeouts.

WHOIS and the SMTP-sending library are imported only after their opt-in actions are used. Registrable-domain extraction uses the packaged Public Suffix List snapshot and never downloads data during a Streamlit session. CI now starts the app through Streamlit's real session test harness and checks that the six-tab UI renders in under ten seconds with both external-network modes off.
