# Meta SMS Gateway

A private, Meta-only Android SMS gateway. It forwards **only** SMS messages
that satisfy **both** conditions to **one** destination — your own
Cloudflare Worker — and nothing else ever leaves the phone:

1. The sender is explicitly allowlisted by you (exact match, case-insensitive).
2. The body is exactly a Meta confirmation code:
   `123456 is your Meta confirmation code.` — six ASCII digits, no extra text.

The allowlist starts **empty**, so nothing is forwarded until you approve
the exact sender ID from a genuine Meta SMS. Every other SMS is discarded
locally: no upload, no log, no storage of the message.

Deployed Worker (this account): `https://meta-sms-gateway.mitov7.workers.dev`
— endpoint: `https://meta-sms-gateway.mitov7.workers.dev/sms/meta`

## How it works

```
Meta SMS -> Android (filter + HMAC sign) -> POST https://<your-worker>/sms/meta
                                          -> Durable Object MetaInbox (newest code only, 5 min)
Owner   -> GET /latest with Bearer SMS_READ_TOKEN -> code once, then deleted
```

- **Android** (`app/`): `SmsBroadcastReceiver` filters, builds the exact
  JSON payload, encrypts it with a Keystore-backed AES-256-GCM key, and
  enqueues only ciphertext via WorkManager. `RequestWorker` decrypts just
  before sending, signs the request (HMAC-SHA256 over the canonical
  string), and POSTs to the single configured HTTPS endpoint. No
  heartbeat, no test endpoint, no message list, no failed-message store.
- **Worker** (`cloudflare-worker/`): verifies the HMAC, timestamp
  (120 s), nonce (replay protection), and device ID; independently
  re-validates the sender and body; stores only the extracted six-digit
  code in the `MetaInbox` Durable Object — newest only, 5-minute lifetime,
  deleted on first authenticated retrieval. No history, no forwarding to
  any external service, no CORS headers, no logging of codes or bodies.

## Exact outbound destinations

| From | Destination | What is sent |
|---|---|---|
| Android app | The one Worker URL you enter in Settings, HTTPS, path exactly `/sms/meta` | Signed JSON payload (version, eventId, sender, body, receivedAt) |
| Worker | None. Only internal Durable Object calls inside the same account | — |

No analytics, crash reporting, Firebase, advertising, or third-party SDK.
The full audit is in [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md).

## 1. Deploy the Worker

Requires Node.js 20+ and `wrangler` (installed as a dev dependency in
`cloudflare-worker/`).

```sh
cd cloudflare-worker
npm ci
npx wrangler deploy
```

This deploys the Worker and its `MetaInbox` Durable Object (SQLite-backed
migration `v1`). Your Worker URL is shown by wrangler; with the default
subdomain it is `https://meta-sms-gateway.<your-subdomain>.workers.dev`.

> **Never paste a live secret into an AI chat, a ticket, or a screenshot.**
> Enter every secret below directly in your own terminal or in the
> Cloudflare dashboard.

### 1a. Generate the read token (your terminal only)

```sh
openssl rand -base64 32
```

Keep the output private. This becomes `SMS_READ_TOKEN`.

### 1b. Set the Worker secrets and vars

```sh
cd cloudflare-worker
npx wrangler secret put SMS_HMAC_SECRET   # paste the value shown in the Android app (step 2c)
npx wrangler secret put SMS_READ_TOKEN   # paste the token from step 1a
```

Set the non-secret vars in the Cloudflare dashboard (Workers & Pages →
`meta-sms-gateway` → Settings → Variables), or in `wrangler.jsonc`:

- `EXPECTED_DEVICE_ID` — the device ID shown in the Android app (step 2c).
  Leave empty until the app is installed; with it empty, no request is
  accepted.
- `META_ALLOWED_SENDER_IDS` — the exact Meta sender ID(s), comma-separated
  (e.g. `META`). Leave empty until you know the exact ID; with it empty,
  the Worker accepts nothing.

After changing vars, redeploy: `npx wrangler deploy`.

### 1c. Verify the Worker is live (no secrets needed)

```sh
curl -s -w "\n%{http_code}\n" https://meta-sms-gateway.<your-subdomain>.workers.dev/
# {"error":"not_found"}  404
curl -s -w "\n%{http_code}\n" https://meta-sms-gateway.<your-subdomain>.workers.dev/latest
# {"error":"unauthorized"}  401
```

## 2. Build and install the Android app

Minimum Android 8.0 (API 26). The app requests only `RECEIVE_SMS`,
`INTERNET`, foreground-service, boot-completed, and notification
permissions.

### Option A — GitHub Actions (recommended)

Push this repository to GitHub. The workflow in
`.github/workflows/build.yml` runs the unit tests and builds a debug APK
on every push to `main`. Download the `meta-sms-gateway-debug` artifact
from the Actions run, copy it to your phone, and install it (allow
"install unknown apps" for your file manager/browser when prompted).

### Option B — Android Studio

Open the repository root in Android Studio, let Gradle sync, then
**Build → Build Bundle(s) / APK(s) → Build APK(s)**. Install
`app/build/outputs/apk/debug/app-debug.apk` on your phone.

### 2a. Grant the SMS permission

Open the app, tap **Settings** if needed, and allow the SMS permission
when asked. Without it, Android never delivers SMS broadcasts to the app
and nothing can be forwarded.

### 2b. Enter the Worker URL and allowlist

In **Settings**:

1. **Worker URL:** `https://meta-sms-gateway.<your-subdomain>.workers.dev/sms/meta`
   (exactly this path; anything else is rejected by the app).
2. **Allowed sender IDs:** one per line. **Leave this empty until you
   have the exact sender ID** — see step 2d. While it is empty, the app
   forwards nothing and only shows observed sender IDs locally to help
   you approve the right one.
3. Tap **Save**.

### 2c. Copy the device ID and HMAC secret into the Worker

In **Settings**:

1. Tap **Copy** next to **Device ID**, and set it as the Worker's
   `EXPECTED_DEVICE_ID` var (step 1b).
2. Tap **Show** next to **HMAC secret** (behind a warning), tap **Copy**,
   and set it as the Worker's `SMS_HMAC_SECRET` secret with
   `npx wrangler secret put SMS_HMAC_SECRET` in your own terminal.
   The secret is generated on the phone (32 random bytes) and stored
   only encrypted under the Android Keystore key. Do not share it.
   If you tap **Regenerate**, you must update the Worker secret too —
   requests signed with the old secret will be rejected with 401.

### 2d. Find the exact Meta sender ID

1. Keep the allowlist empty and ask Meta to send a confirmation code
   (or wait for one). The app records the sender ID only — never the
   body — and shows it in Settings under **Observed senders** while the
   allowlist is empty.
2. Confirm the sender ID is the genuine Meta sender (compare it with
   the sender shown in your messaging app for a real Meta code).
3. Tap the observed sender to add it to the field, tap **Save**, and
   set the same ID in the Worker's `META_ALLOWED_SENDER_IDS` var.
4. The next genuine Meta code SMS is forwarded. Test with a real Meta
   code request; a code from any other sender, or with extra text, is
   discarded.

> Do not assume the sender ID is `META`. Use the exact ID your carrier
> delivers. If Meta uses more than one sender ID, add each one on its
> own line in both places.

## 3. Retrieve the latest code

```sh
curl -s -H "Authorization: Bearer <SMS_READ_TOKEN>" \
  https://meta-sms-gateway.<your-subdomain>.workers.dev/latest
# {"code":"116018","expiresAt":1730000000}   (example)
```

- The code is returned **once** and deleted. A second call returns 404
  until a newer code arrives.
- Codes expire after 5 minutes. Only the newest code is kept.
- The token must be sent as a Bearer header — never in a URL query
  string (query-string tokens are rejected with 401).
- `Cache-Control: no-store` is set on the response.

## 4. Behaviour reference

| Situation | Android | Worker |
|---|---|---|
| Empty allowlist | Discards; records sender ID locally only | 400 (fail closed) |
| Sender not allowlisted | Discards silently | 400 |
| Body is not the exact Meta template | Discards silently | 400 |
| Bad HMAC / wrong device / stale timestamp | — | 401 |
| Replayed nonce / duplicate event | Retried per policy | 409 / 204 (no second OTP) |
| Body over 4 KB, wrong content type | — | 413 / 400 |
| Server error (5xx) | Up to 3 attempts, exponential backoff | 502 from inbox failure |
| Permanent 3xx/4xx | No retry | — |

Accepted POST responses are `204` with an empty body — the OTP is never
returned in a POST response.

## 5. Tests

```sh
# Worker: typecheck + 31 tests
cd cloudflare-worker && npm ci && npx tsc --noEmit && npx vitest run

# Android: 33 unit tests (JUnit 4) + APK build, via Gradle
./gradlew :app:testDebugUnitTest :app:assembleDebug
```

The Android and Worker signing implementations are pinned to the same
fixed test vector (body SHA-256 and HMAC signature), so a drift in
either side fails its own test suite.

## 6. Security properties

- **Filter:** exact sender match + exact six-digit Meta template, on
  both ends, fail closed. An empty allowlist forwards nothing.
- **Transport:** HTTPS only, no redirects, default platform TLS
  verification, no "ignore SSL". `usesCleartextTraffic="false"`.
- **Auth:** HMAC-SHA256 over `POST\n/sms/meta\nTIMESTAMP\nNONCE\nBODY_SHA256`,
  120-second timestamp tolerance, per-attempt fresh nonce, nonce replay
  store (10 min), duplicate event suppression.
- **Storage (phone):** Keystore AES-256-GCM key; HMAC secret, Worker
  URL, allowlist, and device ID stored only as ciphertext. WorkManager
  holds only ciphertext + event ID. No plaintext OTP anywhere on the
  phone, in logs, or in backups (`allowBackup="false"` + exclusion
  rules). No export/import of configuration.
- **Storage (Worker):** only the six-digit code, newest only, 5-minute
  TTL, deleted on first retrieval. No history, no body storage.
- **Privacy:** the payload contains only version, eventId, sender, body,
  and receivedAt. No phone number, IMEI/IMSI, SIM, location, contacts,
  battery, or network data.
- **Logging:** no SMS body, code, secret, header, token, or payload is
  ever logged on either side.

See [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) for the full audit,
including limitations: the APK has not been run on a physical device
from this environment, and the exact Meta sender ID and secrets must be
provisioned by the owner as described above.

## 7. Repository layout

```
app/                          Android app (Meta-only gateway)
cloudflare-worker/            Worker + MetaInbox Durable Object
  src/filter.ts               sender/body filter (mirrors Android)
  src/verify.ts               HMAC / timestamp / nonce verification
  src/inbox.ts                MetaInbox Durable Object
  src/index.ts                routing: POST /sms/meta, GET /latest
  wrangler.jsonc              Worker config (no secrets)
  .dev.vars.example           local-secret placeholders (empty)
.github/workflows/build.yml   CI: unit tests + debug APK
SECURITY_AUDIT.md             full-source security audit report
```

Based on [bogkonstantin/android_income_sms_gateway_webhook](https://github.com/bogkonstantin/android_income_sms_gateway_webhook),
rewritten as a Meta-only gateway. The original multi-destination
forwarder, heartbeat, and plaintext storage code was removed entirely.
