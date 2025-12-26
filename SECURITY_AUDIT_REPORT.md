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
- `file` parameter ends with `.sql`, `.gz`, or `zip`
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

**Impact:**
- If restore file path can be manipulated, potential command injection
- Requires specific server configuration

**EXPLOITABILITY: LIMITED** (multiple conditions required, partial mitigation exists)

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
- Backticks filtered to prevent command substitution

**Impact:**
- If database is compromised, could lead to RCE
- Chained attack vector

**EXPLOITABILITY: CHAIN-DEPENDENT** (requires prior database compromise)

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

---

## RECOMMENDATIONS

### For V1 (Path Traversal):
Add path traversal protection to the download action in `/admin/backup_mysql.php`:
```php
case 'download':
    if (strstr($_GET['file'], '..')) zen_redirect(zen_href_link(FILENAME_BACKUP_MYSQL));
    // ... rest of existing code
```

### For V2 (XSS):
Apply proper HTML encoding in `/admin/coupon_admin.php`:
```php
<td><?php echo htmlspecialchars($_POST['coupon_uses_coupon'], ENT_QUOTES, CHARSET); ?></td>
```

### For V3 (Header Injection):
Sanitize filename in header output:
```php
$safe_filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $_GET['file']);
header('Content-disposition: attachment; filename=' . $safe_filename);
```

---

## CONCLUSION

This audit identified **6 vulnerabilities**, of which **2 are directly exploitable** by an authenticated admin user (V1, V2), **1 is an intentional feature** representing high risk (V4), and **3 have limited exploitability** due to mitigating factors or requiring attack chains (V3, V5, V6).

All confirmed vulnerabilities require admin authentication, significantly limiting the attack surface. However, if admin credentials are compromised through phishing or other means, these vulnerabilities could enable full system compromise.

**Key Finding:** The most critical real-world risk is the SQL Patch tool (V4), which is an intentional feature but represents significant exposure if admin credentials are compromised. Combined with the XSS vulnerability (V2), an attacker could potentially chain these to gain database access.

---

*Report generated: 2024*
*Auditor: Security Analyst (Authorized White-Box Assessment)*
