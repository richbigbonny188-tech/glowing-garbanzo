# Security Audit Report: Deuth Zen Cart CMS

## Executive Summary

This white-box security audit of the Deuth Zen Cart CMS (German customization of Zen Cart) was conducted to identify real, provable security vulnerabilities that are reachable from external entrypoints. The analysis focused on data flow tracing from entrypoints to sinks, with emphasis on SQL injection, cross-site scripting (XSS), path traversal, command injection, and other common web application vulnerabilities.

---

## PHASE 1: ENTRYPOINT MAPPING

### A) Frontend Controllers (HTTP)

| Entrypoint | File Path | Transport | Methods | Parameters | Authentication |
|------------|-----------|-----------|---------|------------|----------------|
| Main Index | `/index.php` | HTTP/HTTPS | GET/POST | `main_page`, `cPath`, `products_id`, etc. | None (public) |
| PayPal IPN | `/ipn_main_handler.php` | HTTPS POST | POST | IPN callback data | PayPal signature |
| MailHive | `/mailhive.php` | HTTP/HTTPS | GET/POST | Various | Internal config |

### B) Admin Controllers (HTTP - requires authentication)

| Entrypoint | File Path | Transport | Methods | Parameters | Authentication |
|------------|-----------|-----------|---------|------------|----------------|
| Admin Index | `/admin/index.php` | HTTPS | GET/POST | Various | Admin session |
| SQL Patch | `/admin/sqlpatch.php` | HTTPS | POST | `query_string`, SQL file upload | Admin session |
| Backup MySQL | `/admin/backup_mysql.php` | HTTPS | GET/POST | `action`, `file` | Admin session |
| Define Pages | `/admin/define_pages_editor.php` | HTTPS | GET/POST | `filename`, `file_contents` | Admin session |
| Developers Toolkit | `/admin/developers_tool_kit.php` | HTTPS | GET/POST | Search patterns | Admin session |
| Coupon Admin | `/admin/coupon_admin.php` | HTTPS | GET/POST | Coupon data | Admin session |
| Uploads | `/admin/uploads.php` | HTTPS | GET | `get`, `oid` | Admin session |

### C) API/Callback Endpoints

| Entrypoint | File Path | Transport | Methods | Parameters | Authentication |
|------------|-----------|-----------|---------|------------|----------------|
| IT Recht Kanzlei | API endpoint via class | HTTPS POST | POST | XML payload | Token-based |
| Payment Callbacks | Various payment modules | HTTPS | POST | Payment data | Module-specific |

---

## PHASE 2: FULL DATA FLOW TRACE

### Flow 1: Admin Backup Download
```
[ENTRYPOINT] /admin/backup_mysql.php?action=download&file=X
[SOURCE] $_GET['file']
[TRANSFORMATIONS]
  - Extension check: substr($_GET['file'], -3) must be 'zip', '.gz', or 'sql'
  - NO path traversal filtering
[SINK] fopen(DIR_FS_BACKUP . $_GET['file'], 'rb') → readfile()
[USER CONTROL PRESERVED: YES]
```

### Flow 2: Admin Coupon Display
```
[ENTRYPOINT] /admin/coupon_admin.php (POST)
[SOURCE] $_POST['coupon_uses_coupon'], $_POST['coupon_uses_user']
[TRANSFORMATIONS]
  - None (direct echo)
[SINK] echo $_POST['coupon_uses_coupon']
[USER CONTROL PRESERVED: YES]
```

### Flow 3: Admin Header Injection
```
[ENTRYPOINT] /admin/backup_mysql.php?action=download&file=X
[SOURCE] $_GET['file']
[TRANSFORMATIONS]
  - Extension check only
[SINK] header('Content-disposition: attachment; filename=' . $_GET['file'])
[USER CONTROL PRESERVED: YES]
```

### Flow 4: SQL Patch Execution
```
[ENTRYPOINT] /admin/sqlpatch.php (POST)
[SOURCE] $_POST['query_string'] or $_FILES['sql_file']
[TRANSFORMATIONS]
  - stripslashes (configurable)
  - Table prefix replacement
[SINK] $db->Execute() with arbitrary SQL
[USER CONTROL PRESERVED: YES] (by design - admin tool)
```

### Flow 5: Define Pages File Write
```
[ENTRYPOINT] /admin/define_pages_editor.php
[SOURCE] $_GET['filename'], $_POST['file_contents']
[TRANSFORMATIONS]
  - Path traversal protection: str_replace('../', '!HACKER_ALERT!', $_GET['filename'])
  - Language directory restriction
[SINK] fwrite($new_file, $file_contents)
[USER CONTROL PRESERVED: PARTIALLY] (path restricted)
```

### Flow 6: Email Archive Resend (CRITICAL - SQL Injection)
```
[ENTRYPOINT] /admin/email_archive_manager.php?action=resend&archive_id=X
[SOURCE] $_GET['archive_id']
[TRANSFORMATIONS]
  - NONE - direct concatenation into SQL query
[SINK] $db->Execute("select * from " . TABLE_EMAIL_ARCHIVE . " where archive_id = " . $_GET['archive_id'])
[USER CONTROL PRESERVED: YES]
```

---

## PHASE 3: CONTROL ELIMINATION FILTER

### Discarded Flows (User Control Eliminated)

| Flow | Location | Reason |
|------|----------|--------|
| Product ID in SQL | Multiple files | Cast to integer: `(int)$_GET['products_id']` |
| Customer ID | Session-based | Uses `$_SESSION['customer_id']` with integer cast |
| Download file validation | `/includes/modules/pages/download/header_php.php` | Database lookup validates ownership |
| Language parameter | Multiple | Whitelisted against database values |
| Category path | `/includes/functions/functions_categories.php` | Integer array processing |

---

## PHASE 4: EXPLOITABILITY ANALYSIS

### VULNERABILITY 1: Path Traversal in Admin Backup Download

**Affected Entrypoint:** `/admin/backup_mysql.php?action=download`

**Vulnerability Class:** CWE-22 (Path Traversal)

**Exact Condition:**
- Admin must be authenticated
- `action` parameter set to `download`
- `file` parameter ends with `.sql`, `.gz`, or `.zip` (note: code checks for `'zip'` without dot, which is consistent with `-3` substring)
- No check for `..` sequences in the download action (unlike delete action)

**Code Location:** `/admin/backup_mysql.php`, lines 285-302
```php
case 'download':
    $extension = substr($_GET['file'], -3);
    if ( ($extension == 'zip') || ($extension == '.gz') || ($extension == 'sql') ) {
        if ($fp = fopen(DIR_FS_BACKUP . $_GET['file'], 'rb')) {
            // File contents sent to browser
        }
    }
```

**Impact:**
- Authenticated admin can read arbitrary files with `.sql`, `.gz`, or `.zip` extensions outside the backup directory
- Potential exposure of configuration files (if renamed with valid extension)
- Information disclosure

**Proof Evidence Required:**
- HTTP request: `GET /admin/backup_mysql.php?action=download&file=../../../etc/passwd.sql`
- Response would contain file contents if path exists and has valid extension
- Log evidence in web server access logs

**EXPLOITABILITY: CONFIRMED** (requires admin authentication)

---

### VULNERABILITY 2: Reflected XSS in Admin Coupon Management

**Affected Entrypoint:** `/admin/coupon_admin.php`

**Vulnerability Class:** CWE-79 (Cross-Site Scripting)

**Exact Condition:**
- Admin must be authenticated
- POST request with `coupon_uses_coupon` or `coupon_uses_user` parameters
- Values echoed without HTML encoding

**Code Location:** `/admin/coupon_admin.php`, lines 713-717
```php
<td><?php echo $_POST['coupon_uses_coupon']; ?></td>
...
<td><?php echo $_POST['coupon_uses_user']; ?></td>
```

**Impact:**
- Self-XSS attack vector in admin panel
- If combined with CSRF, could execute JavaScript in admin context
- Potential session hijacking or admin account compromise

**Proof Evidence Required:**
- POST request with `coupon_uses_coupon=<script>alert('XSS')</script>`
- Response HTML contains unescaped script tag
- Browser executes JavaScript

**EXPLOITABILITY: CONFIRMED** (requires admin session, self-XSS unless combined with CSRF)

---

### VULNERABILITY 3: HTTP Header Injection

**Affected Entrypoints:**
1. `/admin/backup_mysql.php?action=download`
2. `/admin/dsgvo_kundenexport.php`

**Vulnerability Class:** CWE-113 (HTTP Response Splitting)

**Exact Condition:**
- User-controlled filename in Content-Disposition header
- No newline character filtering

**Code Location:**
```php
// backup_mysql.php line 294:
header('Content-disposition: attachment; filename=' . $_GET['file']);

// dsgvo_kundenexport.php line 70:
header("Content-Disposition:attachment; filename=dsgvo_kundendatensatz_kundennummer_".$_GET['cID'].".csv");
```

**Impact:**
- In older PHP versions (< 5.1.2), could inject arbitrary headers
- Modern PHP versions mitigate this but non-sanitized filename could cause parsing issues
- Potential for cache poisoning in specific proxy configurations

**Proof Evidence Required:**
- Request with CRLF characters in filename parameter
- Response header analysis showing injection (version-dependent)

**EXPLOITABILITY: LIMITED** (modern PHP mitigates; requires admin auth)

---

### VULNERABILITY 4: Arbitrary SQL Execution (By Design)

**Affected Entrypoint:** `/admin/sqlpatch.php`

**Vulnerability Class:** CWE-89 (SQL Injection) - By Design

**Exact Condition:**
- Admin authenticated
- Access to SQL Patch tool
- Submit arbitrary SQL via form or file upload

**Impact:**
- Complete database compromise
- Data exfiltration
- Database destruction

**Note:** This is an intentional admin feature, but represents a high-risk attack surface if admin credentials are compromised.

**EXPLOITABILITY: BY DESIGN** (intentional admin tool)

---

### VULNERABILITY 5: Command Execution via Backup Tool

**Affected Entrypoint:** `/admin/backup_mysql.php`

**Vulnerability Class:** CWE-78 (OS Command Injection) - Partially Mitigated

**Exact Condition:**
- Admin authenticated
- `exec()` enabled on server
- Backup/restore operations use shell commands

**Code Location:** Lines 138, 228, 233, 261
```php
$resultcodes = @exec(OS_DELIM . $toolfilename . $dump_params . OS_DELIM, $output, $dump_results);
exec(LOCAL_EXE_GUNZIP . ' ' . $restore_file . ' -c > ' . $restore_from);
exec(LOCAL_EXE_UNZIP . ' ' . $restore_file . ' -d ' . DIR_FS_BACKUP);
```

**Mitigating Factors:**
- Tool filename comes from configuration or detected paths
- File paths constructed from constants + user input
- `escapeshellcmd()` used for password parameter

**Residual Attack Vectors (Partially Mitigated):**
- `$restore_file` is derived from the backup filename / `file` parameter in `/admin/backup_mysql.php` and is concatenated directly into the `exec()` command without shell escaping.
- If an attacker can cause an admin to restore a backup whose filename (or path component) contains shell metacharacters (for example `;`, `&&`, `|`, backticks, or `$()`), those characters may be interpreted by the shell, resulting in command injection.
- Exploitation typically requires: (a) an authenticated admin session, and (b) the ability to influence or control the backup filename (e.g., through file upload, filesystem write, or social engineering of the admin to use a crafted filename).

**Impact:**
- If the restore file path or filename portion of `$restore_file` can be manipulated to include shell metacharacters, there is a potential for command injection in the `exec()` calls shown above.
- Requires specific server configuration (e.g., use of a real shell to execute commands) and the ability to influence backup filenames.

**EXPLOITABILITY: LIMITED** (multiple conditions required; file-path based command injection remains possible via crafted backup filenames / `file` parameter despite partial mitigations)

---

### VULNERABILITY 6: Eval Usage in Configuration

**Affected Entrypoints:** `/admin/modules.php`, `/admin/configuration.php`, `/admin/product_types.php`

**Vulnerability Class:** CWE-95 (Eval Injection)

**Exact Condition:**
- `set_function` stored in database contains PHP code
- Admin modifies configuration values

**Code Location:** `/admin/modules.php` line 344
```php
eval('$keys .= ' . $value['set_function'] . '"' . zen_output_string($value['value'], array('"' => '&quot;', '`' => 'null;return;exit;')) . '", "' . $key . '");');
```

**Mitigating Factors:**
- `set_function` comes from trusted database configuration
- Input value sanitized via `zen_output_string()`
- Backticks are replaced with the literal string `null;return;exit;` via `zen_output_string()`, intended to prevent command substitution

**Impact:**
- If database is compromised, could lead to RCE
- Chained attack vector

**EXPLOITABILITY: CHAIN-DEPENDENT** (requires prior database compromise)

---

### VULNERABILITY 7: SQL Injection in Email Archive Manager (CRITICAL)

**Affected Entrypoint:** `/admin/email_archive_manager.php?action=resend`

**Vulnerability Class:** CWE-89 (SQL Injection)

**Exact Condition:**
- Admin must be authenticated
- `action` parameter set to `resend`
- `archive_id` parameter is directly concatenated into SQL query without sanitization

**Code Location:** `/admin/email_archive_manager.php`, line 32
```php
if ($action == 'resend') {
    // collect the e-mail data
    $email_sql = $db->Execute("select * from " . TABLE_EMAIL_ARCHIVE . " where archive_id = " . $_GET['archive_id']);
```

**Note:** The `delete` action on line 42 correctly uses `(int)$_GET['archive_id']` but the `resend` action does not.

**Impact:**
- Full SQL injection allowing data extraction, modification, or deletion
- Potential for authentication bypass through UNION-based injection
- Database takeover if database user has elevated privileges

**Proof Evidence Required:**
- HTTP request: `GET /admin/email_archive_manager.php?action=resend&archive_id=1 OR 1=1--`
- Response change or SQL error message indicating injection
- Time-based blind injection: `archive_id=1 AND SLEEP(5)--`

**EXPLOITABILITY: CONFIRMED** (requires admin authentication, but exploitable)

---

## PHASE 5: ATTACK CHAINS

### Chain 1: Admin Credential Theft → Full Compromise
```
[Entrypoint] Admin XSS (coupon_admin.php) + CSRF
    ↓
[Intermediate Effect] Execute JavaScript in admin context
    ↓
[Intermediate Effect] Steal admin session/credentials OR access SQL Patch
    ↓
[Final Impact] Full database compromise via sqlpatch.php
```

**Provability:** Each step is independently verifiable. Chain requires:
1. Ability to deliver malicious link to admin
2. Admin clicks link while authenticated
3. JavaScript executes to access sqlpatch.php

### Chain 2: Path Traversal → Information Disclosure
```
[Entrypoint] /admin/backup_mysql.php?action=download&file=../sensitive.sql
    ↓
[Intermediate Effect] Read files with .sql/.gz/.zip extension outside backup dir
    ↓
[Final Impact] Potential exposure of SQL dumps or configuration backups
```

**Provability:** Verifiable with single HTTP request if admin session exists.

---

## CONFIRMED VULNERABILITIES SUMMARY

| ID | Vulnerability | Severity | Exploitability | Auth Required |
|----|--------------|----------|----------------|---------------|
| V1 | Path Traversal in Backup Download | Medium | Confirmed | Admin |
| V2 | Reflected XSS in Coupon Admin | Medium | Confirmed | Admin |
| V3 | HTTP Header Injection | Low | Limited | Admin |
| V4 | SQL Execution (by design) | Critical | By Design | Admin |
| V5 | Partial Command Injection | Medium | Limited | Admin |
| V6 | Eval in Configuration | High | Chain-dependent | Admin + DB |
| **V7** | **SQL Injection in Email Archive Manager** | **Critical** | **Confirmed** | Admin |

---

## RECOMMENDATIONS

### For V1 (Path Traversal):
Add robust path traversal protection to the download action in `/admin/backup_mysql.php`:
```php
case 'download':
    $backupDir = realpath(DIR_FS_BACKUP);
    $requested = isset($_GET['file']) ? basename($_GET['file']) : '';

    // Build and validate the full path to the requested backup file
    $filePath = $backupDir !== false && $requested !== ''
        ? realpath($backupDir . DIRECTORY_SEPARATOR . $requested)
        : false;

    if ($backupDir === false ||
        $filePath === false ||
        strpos($filePath, $backupDir . DIRECTORY_SEPARATOR) !== 0 ||
        !is_file($filePath)
    ) {
        zen_redirect(zen_href_link(FILENAME_BACKUP_MYSQL));
    }
    // ... rest of existing code that uses $filePath for the download
```

### For V2 (XSS):
Apply proper HTML encoding in `/admin/coupon_admin.php`:
```php
<td><?php echo htmlspecialchars($_POST['coupon_uses_coupon'], ENT_QUOTES, 'UTF-8'); ?></td>
```

### For V3 (Header Injection):
Validate the requested backup file against the backup directory and use a safe filename in the header output:
```php
$backupDir = DIR_FS_BACKUP; // Directory where backup files are stored
$requested  = isset($_GET['file']) ? (string) $_GET['file'] : '';

// Normalize to a simple filename and build the full path in the backup directory
$filename   = basename($requested);
$filePath   = realpath($backupDir . DIRECTORY_SEPARATOR . $filename);
$backupRoot = realpath($backupDir);

// Ensure the resolved path is inside the backup directory and points to an existing file
if ($filename === '' ||
    $filePath === false ||
    $backupRoot === false ||
    strpos($filePath, $backupRoot) !== 0 ||
    !is_file($filePath)
) {
    // Invalid or non-existent backup file requested – handle gracefully
    zen_redirect(zen_href_link(FILENAME_BACKUP_MYSQL));
}

// At this point, $filename is a valid backup filename under $backupDir
header('Content-Disposition: attachment; filename="' . $filename . '"');
```

### For V7 (SQL Injection - CRITICAL):
Apply integer cast to `archive_id` parameter in `/admin/email_archive_manager.php`:
```php
if ($action == 'resend') {
    // collect the e-mail data
    $email_sql = $db->Execute("select * from " . TABLE_EMAIL_ARCHIVE . " where archive_id = " . (int)$_GET['archive_id']);
```

---

## CONCLUSION

This audit identified **7 vulnerabilities**, of which **3 are directly exploitable** by an authenticated admin user (V1, V2, **V7**), **1 is an intentional feature** representing high risk (V4), and **3 have limited exploitability** due to mitigating factors or requiring attack chains (V3, V5, V6).

**CRITICAL FINDING - SQL Injection (V7):** The most severe newly discovered vulnerability is a SQL injection in `/admin/email_archive_manager.php` where `$_GET['archive_id']` is directly concatenated into a SQL query without sanitization. This allows an authenticated admin to execute arbitrary SQL commands.

All confirmed vulnerabilities require admin authentication, significantly limiting the attack surface. However, if admin credentials are compromised through phishing or other means, these vulnerabilities could enable full system compromise.

**Key Finding:** The most critical real-world risk is the SQL Patch tool (V4), which is an intentional feature but represents significant exposure if admin credentials are compromised. Combined with the XSS vulnerability (V2), an attacker could potentially chain these to gain database access.

---

*Report generated: 2024*
*Auditor: Security Analyst (Authorized White-Box Assessment)*
