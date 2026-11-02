# Security Audit Report — Meta-only SMS Gateway v3.0.0

Date: 3 November 2026 (IST). Auditor: Muse (agent), full-source audit of the
finished code in this repository, after implementation. This report does not
claim security from compilation alone: every claim below names the code or
test that establishes it, and the limitations in §8 are part of the finding.

## 1. Scope

- Android app: `app/src/main/java/tech/bogomolov/incomingsmsgateway/`
  (12 classes), `app/src/main/AndroidManifest.xml`,
  `app/src/main/res/xml/{backup_rules,data_extraction_rules}.xml`,
  `app/build.gradle`, `app/src/main/res/values/strings.xml`, layouts.
- Cloudflare Worker: `cloudflare-worker/src/{filter,verify,inbox,index}.ts`,
  `cloudflare-worker/wrangler.jsonc`, `package.json`, `.dev.vars.example`.
- Tests: `app/src/test/java/...` (JUnit 4), `cloudflare-worker/test/` (Vitest).
- Out of scope for this audit: the original upstream app (audited separately
  in Phase 1 — see §2), the deployed Cloudflare account settings, and the
  physical phone. No on-device test was run (see §8).

## 2. Phase 1 findings (original app) — why it was rewritten, not patched

The original app forwarded *any* SMS to *any* user-configured URL, with
sender matching by exact string or substring regex, an empty filter meaning
"forward everything", HTTP allowed (`usesCleartextTraffic="true"`), an
"ignore SSL" option, HMAC over the raw body only, and all rules, secrets and
failed payloads (full SMS text, URL, headers, HMAC secret) in plaintext
SharedPreferences and plaintext backup export. No Keystore, no encryption,
no replay protection, heartbeat POSTs to a second user-configured URL.
None of that code survives: every original forwarding, heartbeat, storage
and test-request class was deleted. The only surviving original files are
the rewritten activities/receiver/worker/service and the boot receiver.

## 3. Method

- Read every Android and Worker source file in full.
- Grepped the whole tree for: `HttpURLConnection`, `openConnection`,
  `new URL`, `Socket`, `OkHttp`, `Retrofit`, `Volley`, `WebView`, `fetch`,
  `console.`, `Log.`, `getSharedPreferences`, file output, `ignoreSsl`,
  `TrustManager`, `HostnameVerifier`, `cleartext`, `http://`, hardcoded
  domains, `api_key`, `password`, `Bearer`, and CORS headers.
- Verified the filter, signing and encryption by running the test suites
  (see §7) and by a fixed cross-platform signing vector computed
  independently in Java and in TypeScript (identical output).
- Verified all Android sources compile against the real API-33 `android.jar`
  and the real WorkManager 2.7.1 `classes.jar` with `javac` (Gradle's daemon
  does not run in this sandbox — see §8; stubs were used only for
  AppCompat/R, which AGP generates at build time).

## 4. Exact outbound destinations

There is exactly **one** permitted destination in the entire codebase:

- **Android:** one `HttpsURLConnection` POST, in `MetaHttpClient.post()`,
  to the single user-configured Worker URL, which must be HTTPS with path
  exactly `/sms/meta` (`MetaHttpClient.isAllowedEndpoint` /
  `isValidConfiguredUrl`). The URL is stored encrypted (see §5) and is
  entered by the owner in Settings. No other host, path, or scheme can be
  reached: non-HTTPS, wrong host/port, any query or fragment, userinfo, or
  any other path is refused before a connection is opened, and redirects
  are disabled (`setInstanceFollowRedirects(false)`). No analytics, crash
  reporting, Firebase, advertising, or third-party SDK is present; no
  OkHttp/Retrofit/Volley/WebView exists in the tree. The heartbeat, test
  request, and test-heartbeat endpoints of the original app are deleted.
- **Worker:** no outbound `fetch` to any external service exists. The only
  `fetch` calls are internal Durable Object stub calls
  (`http://inbox/reserve`, `http://inbox/consume`) to the bound
  `MetaInbox` object in the same account. No forwarding, webhook, email,
  or third-party call of any kind is present in Worker source.
- **Build tooling only:** Gradle/Maven downloads dependencies at build
  time; that is not an app runtime destination.

## 5. Findings — Android

### 5.1 Meta-only filter (fail closed) — PASS
`SmsBroadcastReceiver` is the only SMS entry point. It forwards nothing
unless `MetaFilter.accepts()` returns true, which requires BOTH:
(a) the sender, trimmed and lower-cased, exactly equals an entry in the
allowlist (also trimmed/lower-cased; `*` is rejected at save time and in
`dedupeAllowlist`), and (b) the body matches, case-insensitively,
`^\s*([0-9]{6})\s+is your Meta confirmation code\.?\s*$` — exactly six ASCII
digits, no extra text. An empty allowlist accepts nothing and only records
the sender ID locally (see §5.4). Rejected messages return silently: no
upload, no log line containing sender/body, no storage of the body. The
regression test `NoNetworkOnRejectTest` asserts every rejection class
never reaches forwarding, and forwarding requires `MetaFilter.accepts`
only. The Worker re-validates independently (see §6.1).

### 5.2 Single HTTPS destination, no redirects, default TLS — PASS
`MetaHttpClient` is the only HTTP client. HTTPS only, POST only,
15-second timeouts, fixed-length body, default platform TLS verification
and the default hostname verifier explicitly restored — no custom
`TrustManager`, no permissive verifier, no "ignore SSL" option anywhere.
`usesCleartextTraffic="false"` in the manifest. Response bodies are
drained and discarded without logging.

### 5.3 HMAC — PASS
`Signing` builds the exact canonical string
`POST\n/sms/meta\nTIMESTAMP\nNONCE\nSHA256_HEX_OF_EXACT_RAW_JSON_BODY`
(no trailing newline) and HMAC-SHA256 over it with the raw 32-byte secret.
Headers sent: `X-Device-Id`, `X-Timestamp` (seconds), `X-Nonce` (16 random
bytes, 32 hex chars), `X-Signature` (lowercase hex). A fresh timestamp and
nonce are generated for *every* attempt, including retries, in
`RequestWorker`; the `eventId` is unchanged across retries of the same
message, so the Worker can de-duplicate. Verified against RFC 4231 Test
Case 2 and a fixed vector shared with the Worker (see §7).

### 5.4 Secrets and storage — PASS, with two documented trade-offs
- HMAC secret: 32 random bytes, generated on first run by
  `SecureStore.getOrCreateHmacSecret`, stored only as an AES-256-GCM
  ciphertext under a Keystore key (alias `meta_sms_gateway_key`, 256-bit,
  GCM, randomised encryption). The secret is displayed only after an
  explicit Show tap behind a warning dialog, for the owner to enter via
  `wrangler secret put` in their own terminal. It is never logged.
- Keystore key: `setUserAuthenticationRequired(false)`. **Trade-off,
  deliberate:** background SMS receipt while the phone is locked must be
  able to decrypt; requiring authentication would break the gateway.
  The key is Keystore-backed (hardware-backed where the device offers
  it) and never leaves the Keystore; only ciphertexts are stored.
- Worker URL, allowlist, device ID, accepted-count: all stored as
  encrypted blobs in private SharedPreferences `meta_secure`. Nothing
  sensitive is stored in plaintext except the observed-sender list (see
  next point) and the app's own code/resources.
- Observed senders: sender IDs only, never a body, in a separate private
  file, capped at 20, shown only while the allowlist is empty, cleared
  once a sender is approved. **Trade-off, deliberate:** this is the
  setup aid that lets the owner approve the exact sender ID without
  guessing; it stores no message content and is never uploaded.
- WorkManager Data holds only ciphertext, `eventId`, and retry count
  (`RequestWorker.DATA_CIPHERTEXT/DATA_EVENT_ID/DATA_MAX_RETRIES`). No
  plaintext OTP, URL, header, or secret is ever placed in WorkManager
  Data, and failed payloads are never persisted (the original
  `FailedMessage` store was deleted). Plaintext payload bytes are zeroed
  in a `finally` block in both the receiver and the worker.
- Backup: `allowBackup="false"`, plus `backup_rules.xml` /
  `data_extraction_rules.xml` excluding `shared_pref`, `database`,
  `file` (and `external` for backup) as defence in depth. No export/import
  of configuration exists. `ACCESS_NETWORK_STATE` was removed; the
  manifest requests only `INTERNET`, `RECEIVE_SMS`, `FOREGROUND_SERVICE`,
  `RECEIVE_BOOT_COMPLETED`, `POST_NOTIFICATIONS`. No contacts, location,
  call-log, or `SEND_SMS` permission. No `READ_CONTACTS`/`READ_SMS`
  history access: only live `SMS_RECEIVED` broadcasts are seen.
- Payload contents: exactly
  `{"version":1,"eventId":"...","sender":"...","body":"...","receivedAt":"..."}`.
  No phone number, IMEI, IMSI, SIM, location, contacts, battery, or
  network data is included (the original `DeviceInfo` placeholders were
  deleted).
- Logging: five `Log.e` calls exist in total, all fixed strings with no
  arguments (`sms parse failed`, `config unavailable, discarding`,
  `payload encryption failed, discarding`, `decrypt or config failed`,
  `network failure`). No sender, body, code, secret, header, token, URL,
  or payload is ever logged on Android. No log viewer or message list
  exists in the UI.

### 5.5 Retries — PASS
`MetaHttpClient.classify`: 2xx success; 3xx (redirects are never
followed, so a 3xx is treated as permanent) and all 4xx (400/401/404/
405/409/413) permanent — no retry; 5xx retry. WorkManager allows at most
3 attempts with exponential backoff and a `NetworkType.CONNECTED`
constraint. A permanent rejection never loops forever.

### 5.6 Component exposure — PASS (one fix applied during this audit)
- `SmsBroadcastReceiver`: `exported="true"` with
  `android:permission="android.permission.BROADCAST_SMS"` — only the
  system can deliver `SMS_RECEIVED`. Correct.
- `BootCompletedReceiver`: `exported="true"` for the system broadcast.
  Correct; it only starts the foreground service.
- `SmsReceiverService`: was `exported="true"` in the original manifest;
  **changed to `exported="false"` during this audit** — it is started
  only by the app itself and exposes no data.
- Activities: `SettingsActivity` is `exported="false"`; `MainActivity`
  is the launcher. Correct.

### 5.7 Known Android limitations (not failures)
- `targetSdkVersion`/`compileSdkVersion` 33, `minSdkVersion` 26. A
  foreground-service type is not declared; that is acceptable at
  target 33 but would be required if the target is raised to 34+.
- The foreground service shows a persistent notification ("Meta SMS
  Gateway is running") and does no network work itself.
- The app has not been run on a physical device in this audit (see §8);
  Keystore behaviour, SMS receipt, and the Rabby-style permission flow
  for `RECEIVE_SMS`/`POST_NOTIFICATIONS` are verified by code review
  and unit tests only.

## 6. Findings — Cloudflare Worker

### 6.1 Routing and independent validation — PASS
Only `POST /sms/meta` and `GET /latest` exist; anything else is 404,
wrong methods are 405, and no CORS headers are emitted at all (a browser
fetch will be blocked by CORS; the owner reads via `curl` with a Bearer
token). `POST /sms/meta` requires `Content-Type: application/json`, a
body of at most 4096 bytes (header and actual length both checked, 413),
exactly the five allowed JSON keys, `version` 1, bounded string lengths,
and a parseable `receivedAt`, then re-runs the identical sender/regex
filter against `META_ALLOWED_SENDER_IDS`. An empty allowlist accepts
nothing. Authenticated-but-not-Meta requests are discarded with 400 and
create no OTP.

### 6.2 HMAC / replay / timestamp — PASS
`verify.ts` checks, in order: device ID equals `EXPECTED_DEVICE_ID`,
secret present, timestamp all-digits and within 120 seconds of the
Worker clock, nonce 1–128 chars, signature 64 hex chars, and HMAC over
the exact raw body bytes against the canonical string, compared in
constant time. Secret decoding accepts 64-char hex, base64 (the form
the Android app displays), or raw UTF-8 bytes — all must decode to
exactly 32 bytes for the first two forms. Nonces are stored in the
Durable Object for 600 seconds; a replayed nonce returns 409. A
duplicate `eventId` returns 204 without creating a second OTP. All
failures return 401/400 with no detail that leaks which check failed
beyond the status code, and nothing is logged (`console.` does not
appear in Worker source).

### 6.3 Durable Object storage — PASS
`MetaInbox` stores, per object: `nonce:<nonce>` and `event:<eventId>`
(600 s each, for replay/duplicate protection) and a single `current`
entry `{code, expiresAt}` with a 300-second lifetime. Only the newest
OTP is kept — a new accepted code replaces the previous one. `consume`
returns the code and deletes it: first authenticated retrieval only.
Expired entries are lazily removed on every request. The complete SMS
body is never stored; only the extracted six-digit code is. There is no
history, no listing endpoint, and no way to retrieve an expired or
already-consumed code.

### 6.4 Retrieval endpoint — PASS
`GET /latest` rejects any query-string token key (`token`, `auth`,
`access_token`, `sms_read_token`) with 401, requires
`Authorization: Bearer <SMS_READ_TOKEN>` compared in constant time,
returns only `{code, expiresAt}` with `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`, or 404 when no valid code exists.
The OTP is never returned in any `POST /sms/meta` response (204, empty
body). The read token is a separate secret from the HMAC secret and
must be set with `wrangler secret put SMS_READ_TOKEN`.

### 6.5 Configuration — PASS
`wrangler.jsonc` contains no secrets: `EXPECTED_DEVICE_ID` and
`META_ALLOWED_SENDER_IDS` default to empty strings (fail closed) and
must be set as Worker vars; `SMS_HMAC_SECRET` and `SMS_READ_TOKEN` are
secrets only, set via `wrangler secret put` or the dashboard.
`.dev.vars` (local secrets) is gitignored, with `.dev.vars.example`
holding empty placeholders only. The Durable Object migration is
declared (`v1`, `new_classes: ["MetaInbox"]`) with binding `META_INBOX`.
No secret value appears anywhere in this repository (verified by grep);
the only secret *names* present are in code, docs, and the example file.

## 7. Tests run

- Android (JUnit 4, plain `javac`/`java`, JDK 17, real code, no
  Android runtime): **33 tests, all passing** — `MetaFilterTest` (9),
  `SigningTest` (8, incl. RFC 4231 Case 2 and the fixed cross-platform
  vector), `AesGcmTest` (5), `MetaHttpClientTest` (9), 
  `NoNetworkOnRejectTest` (2). The fixed vector
  (body SHA-256 `36f98720…559c8`, signature `f914d836…47f04`) was
  computed independently in Java and in TypeScript with identical
  results, proving the Android signer and the Worker verifier agree.
- Worker (`tsc --noEmit` clean; Vitest): **31 tests, all passing** —
  `filter` (8), `verify` (8, incl. tampered body, expired/boundary
  timestamp, unknown device, secret encodings, cross-platform vector),
  `inbox` (6, incl. newest-only, replay, duplicate, consume-once,
  expiry), `worker` (8, incl. 204 accept with empty body, consume-once
  retrieval, token rejection, oversized/wrong-type/wrong-method).
- Not run: Gradle unit tests and the APK build (Gradle daemon failure
  in this sandbox — see §8). The GitHub Actions workflow in
  `.github/workflows/build.yml` runs the same tests and builds the APK
  on a runner.

## 8. Limitations — what this audit does NOT establish

1. **No APK was built or installed in this audit.** The local Gradle
   daemon fails to dispatch messages to its own daemon process in this
   sandbox (JDK 17 and JDK 21, fresh Gradle user homes, empty projects
   fail identically; loopback sockets otherwise work in the VM). The
   APK must be built by the provided GitHub Actions workflow or by
   Android Studio, and installed on the owner's phone before any
   end-to-end claim can be made.
2. **No on-device test.** SMS receipt, Keystore decryption while
   locked, WorkManager delivery, and the exact sender ID as delivered
   by the carrier (which determines the allowlist entry) are unverified
   until the owner installs the APK and receives a real Meta SMS.
3. **Worker not yet deployed at audit time.** Deployment, the Workers
   subdomain, and the live signed-request check are separate steps; this
   report covers the code that will be deployed, not a live endpoint.
4. **Operational secrets are the owner's responsibility.** The HMAC
   secret and read token must be generated with a CSPRNG, entered only
   via terminal/dashboard, and the HMAC secret copied from the app must
   match the Worker secret exactly, or every request will be rejected
   with 401. The device ID shown in the app must match
   `EXPECTED_DEVICE_ID`, and `META_ALLOWED_SENDER_IDS` must contain the
   exact sender ID from a genuine Meta SMS — none of these values is
   known to, or set by, this audit.
5. **Threat-model boundary.** This gateway protects message content in
   transit and at rest on the phone and in the Worker, and restricts
   forwarding to approved Meta codes. It does not protect against a
   compromised phone OS, a compelled Cloudflare account, SIM-swap or
   sender-ID spoofing by the carrier path (the filter trusts the
   originating address as delivered by Android), or shoulder-surfing of
   the displayed HMAC secret. Those are outside the stated requirements.

## 9. Verdict

Subject to the limitations in §8, the code as audited implements the
stated specification: Meta-only, fail-closed filtering on both ends;
one HTTPS destination, no redirects, default TLS; HMAC-SHA256 with
replay and timestamp protection; Keystore-backed AES-256-GCM storage
with no plaintext OTP in WorkManager, logs, or backups; a Durable
Object inbox holding only the newest code for at most five minutes,
deleted on first retrieval; and no external forwarding anywhere.
No requirement was found to be silently weakened. The two issues found
during the audit (a missing `NoSuchProviderException` catch, and the
exported foreground service) were fixed in the audited code.
