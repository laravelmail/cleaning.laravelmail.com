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
