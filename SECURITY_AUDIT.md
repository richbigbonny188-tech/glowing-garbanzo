# White-box Security Audit – Zen Cart (glowing-garbanzo)

## Phase 1 — Entrypoint Mapping
| Entrypoint | File/Handler | Transport/Method | Parameters | Auth/Trust |
| --- | --- | --- | --- | --- |
| `/ajax.php` | front controller dispatching to `includes/classes/ajax/zc*` classes | HTTP GET (expects `X-Requested-With: XMLHttpRequest`) | `act` (class suffix), `method` (method name); per handler additional POST params | No authentication enforced in controller; CORS `Access-Control-Allow-Origin: *` |
| `/itrk-api.php` | IT-Recht Kanzlei API (`it_recht_kanzlei_api`) | HTTP POST (XML body) | XML elements: `action`, `api_version`, `user_auth_token`, `rechtstext_*` fields | Requires constants (`IT_RECHT_KANZLEI_STATUS=='ja'` and `IT_RECHT_KANZLEI_TOKEN`) to pass checks |
| `/ipn_main_handler.php` | PayPal IPN handler | HTTP POST | PayPal IPN fields | Relies on PayPal POST; no app-level auth |
| `/mailhive.php` | MailBeez bootstrap | HTTP GET | none | Falls back to installer notice when `mailhive/common/main/inc_mailhive.php` missing; no auth |
| `/mailhive/cloudbeez/cloudloader_core.php` | MailBeez Cloudloader installer/updater | HTTP GET/POST | Optional `cloudloader_mode`; POST `handler`, `step`, etc. routed inside `Cloudloader::run` | No authentication; intended for manual install/update |
| `/mailhive/cloudbeez/test_connection/test_curl.php` | Cloudloader speed-test | HTTP GET | none | No auth |

## Phase 2 — Data Flow Traces

### `/ajax.php` → `zcAjaxAdminNotifications::forget`
- **Source:** `$_GET['act']=adminNotifications`, `$_GET['method']=forget` with POST `key`, `admin_id`.
- **Transformations:** Controller validates class/method existence, instantiates `zcAjaxAdminNotifications`, then `forget()` reads `$_POST` values directly; values are bound via `$db->bindVars` into SQL insert/upsert on `TABLE_ADMIN_NOTIFICATIONS`.
- **Sink:** Database write `INSERT ... ON DUPLICATE KEY UPDATE ... dismissed=1` (line 24–29 in `includes/classes/ajax/zcAjaxAdminNotifications.php`).
- **User control preserved:** Yes — no authentication/authorization or CSRF token required; CORS allows cross-origin calls.

### `/itrk-api.php` XML parameters
- **Source:** Raw POST body parsed as XML.
- **Transformations:** Validated for non-empty, well-formed XML; token check against `IT_RECHT_KANZLEI_TOKEN`; language/type whitelists; PDF downloads restricted to hardcoded host list.
- **Sink:** Database updates to EZ-Pages content and optional PDF writes.
- **User control preserved:** No — requires correct token and passes multiple whitelists; flows discarded in Phase 3.

### `/mailhive/cloudbeez/cloudloader_core.php` installer handlers
- **Source:** POST `handler=onInstallStep` with `step` values.
- **Transformations:** `Cloudloader::run` dispatches to `onInstallStep`; steps fetch packages from `cloudbeez.com` and deploy to filesystem.
- **Sink:** Filesystem writes under catalog root.
- **User control preserved:** Partially — handler freely reachable without auth, but payload source fixed to vendor endpoints (not attacker-controlled).

## Phase 3 — Control Elimination
- `/itrk-api.php` requests require a shared secret token (`IT_RECHT_KANZLEI_TOKEN`) and enforce whitelisted languages/types plus strict host allowlist for PDF downloads; user control effectively lost before any sensitive sink → **discarded**.
- Cloudloader installer fetches code only from fixed vendor URLs; attacker cannot influence payload without compromise of upstream transport → **discarded for exploitability here**.

## Phase 4 — Confirmed Exploitability

### Vulnerability 1: Unauthenticated admin-notification dismissal via `/ajax.php`
- **Class:** Authorization bypass / privilege escalation.
- **Condition:** Any unauthenticated HTTP client can call `/ajax.php?act=adminNotifications&method=forget` with `X-Requested-With: XMLHttpRequest` and POST body `key=<notification>` & `admin_id=<target>`.
- **Impact:** Inserts/updates rows in `TABLE_ADMIN_NOTIFICATIONS`, marking arbitrary admin notifications as dismissed. An attacker can suppress security/maintenance alerts for all admins (e.g., admin_id=1), hiding critical warnings.
- **Evidence to prove:**  
  ```
  curl -X POST 'https://<host>/ajax.php?act=adminNotifications&method=forget' \
       -H 'X-Requested-With: XMLHttpRequest' \
       -d 'key=test&admin_id=1'
  ```  
  Observe JSON response `{"data":true}` and a corresponding row/updated row in `admin_notifications` with `dismissed=1`.
- **Why it matters:** Direct, unauthenticated modification of admin-facing state enables an attacker to hide alerts, delaying detection of other issues and violating integrity of administrative data.

## Phase 5 — Chaining
No additional chains proven beyond the single confirmed vulnerability.

## Priority check — RCE / SQLi
- Ajax handlers reachable without authentication (`includes/classes/ajax/zcAjax*.php`) bind user input via `$db->bindVars` and contain no eval/exec, so no SQL injection or code-execution sink was found.
- Exec/eval usages uncovered (`admin/backup_mysql.php`, `admin/modules.php`, `admin/configuration.php`) are constrained to the admin backend guarded by `IS_ADMIN_FLAG`/session auth, keeping them out of unauthenticated reach.
- Cloudloader code execution remains restricted to vendor-hosted payloads and was not found to be attacker-controlled.

## Conclusion
One exploitable vulnerability was proven (unauthenticated admin notification dismissal). All other reviewed entrypoints either enforced sufficient control (token/whitelist) or relied on fixed upstream payloads without attacker influence. No further exploitable vulnerabilities were proven.
