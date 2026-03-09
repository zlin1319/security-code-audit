# CWE to Rule Mapping

## CWE Top 25 (2023) Coverage

| Rank | CWE ID | CWE Name | Rule ID(s) | Severity |
|------|--------|----------|------------|----------|
| 1 | CWE-787 | Out-of-bounds Write | *Memory safety - see notes* | Critical |
| 2 | CWE-79 | Cross-site Scripting | xss-001, xss-002 | High |
| 3 | CWE-89 | SQL Injection | sqli-001 | Critical |
| 4 | CWE-416 | Use After Free | *Memory safety - see notes* | Critical |
| 5 | CWE-78 | OS Command Injection | cmdi-001 | Critical |
| 6 | CWE-20 | Improper Input Validation | *Multiple - foundational* | Variable |
| 7 | CWE-125 | Out-of-bounds Read | *Memory safety - see notes* | High |
| 8 | CWE-22 | Path Traversal | pathtraversal-001 | High |
| 9 | CWE-352 | Cross-Site Request Forgery | csrf-001 | Medium |
| 10 | CWE-434 | Unrestricted File Upload | fileupload-001 | High |
| 11 | CWE-862 | Missing Authorization | auth-002 | High |
| 12 | CWE-476 | NULL Pointer Dereference | *Code quality* | Medium |
| 13 | CWE-287 | Improper Authentication | auth-001 | High |
| 14 | CWE-190 | Integer Overflow | *Arithmetic* | Medium |
| 15 | CWE-502 | Deserialization of Untrusted Data | deserialization-001 | Critical |
| 16 | CWE-77 | Command Injection | cmdi-001 | Critical |
| 17 | CWE-119 | Buffer Overflow | *Memory safety* | Critical |
| 18 | CWE-798 | Use of Hard-coded Credentials | infoleak-001 | High |
| 19 | CWE-918 | Server-Side Request Forgery | ssrf-001 | High |
| 20 | CWE-306 | Missing Authentication | auth-002 | Critical |
| 21 | CWE-362 | Race Condition | race-001 | Medium |
| 22 | CWE-269 | Improper Privilege Management | auth-003 | High |
| 23 | CWE-94 | Code Injection | codeinjection-001 | Critical |
| 24 | CWE-863 | Incorrect Authorization | auth-003 | High |
| 25 | CWE-276 | Incorrect Default Permissions | misconfig-001 | Medium |

## OWASP Top 10 (2021) Coverage

| OWASP ID | Name | Mapped CWEs | Rule ID(s) |
|----------|------|-------------|------------|
| A01:2021 | Broken Access Control | CWE-200, CWE-201, CWE-285, CWE-352, CWE-639 | auth-002, auth-003, pathtraversal-001 |
| A02:2021 | Cryptographic Failures | CWE-327, CWE-328, CWE-330, CWE-916 | crypto-001, crypto-002, crypto-003 |
| A03:2021 | Injection | CWE-79, CWE-89, CWE-73, CWE-78 | sqli-001, xss-001, xss-002, cmdi-001, codeinjection-001 |
| A04:2021 | Insecure Design | CWE-209, CWE-256, CWE-501, CWE-522 | *Architecture review* |
| A05:2021 | Security Misconfiguration | CWE-16, CWE-611, CWE-1004 | misconfig-001 |
| A06:2021 | Vulnerable Components | CWE-1104 | dependency-001 |
| A07:2021 | Auth Failures | CWE-287, CWE-306, CWE-798 | auth-001, auth-002, infoleak-001 |
| A08:2021 | Data Integrity Failures | CWE-345, CWE-502, CWE-565 | deserialization-001 |
| A09:2021 | Logging Failures | CWE-117, CWE-223, CWE-532 | infoleak-001 |
| A10:2021 | SSRF | CWE-918 | ssrf-001 |

## Rule to CWE Reference

### sqli-001: SQL Injection
- **Primary CWE**: CWE-89 (Improper Neutralization of Special Elements in SQL Command)
- **Related**: CWE-564 (SQL Injection: Hibernate), CWE-943 (Improper Neutralization in Data Query Logic)

### xss-001: Reflected XSS
- **Primary CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **Related**: CWE-87 (Improper Neutralization of Alternate XSS Syntax), CWE-692 (Incomplete Denylist)

### xss-002: Stored XSS
- **Primary CWE**: CWE-79
- **Related**: CWE-80 (Basic XSS), CWE-81 (Improper Neutralization of Script in Error Message)

### cmdi-001: Command Injection
- **Primary CWE**: CWE-78 (Improper Neutralization of OS Command Special Elements)
- **Related**: CWE-88 (Argument Injection), CWE-214 (Process Control)

### pathtraversal-001: Path Traversal
- **Primary CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Related**: CWE-23 (Relative Path Traversal), CWE-36 (Absolute Path Traversal), CWE-73 (External Control of File Path)

### deserialization-001: Insecure Deserialization
- **Primary CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Related**: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

### ssrf-001: Server-Side Request Forgery
- **Primary CWE**: CWE-918 (Server-Side Request Forgery)
- **Related**: CWE-611 (Improper Restriction of XML External Entity Reference - XXE)

### auth-001: Weak Authentication
- **Primary CWE**: CWE-287 (Improper Authentication)
- **Related**: CWE-308 (Use of Single-factor Authentication), CWE-640 (Weak Password Recovery)

### auth-002: Missing Authentication
- **Primary CWE**: CWE-306 (Missing Authentication for Critical Function)
- **Related**: CWE-862 (Missing Authorization)

### auth-003: Broken Authorization / IDOR
- **Primary CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Related**: CWE-863 (Incorrect Authorization), CWE-269 (Improper Privilege Management)

### infoleak-001: Information Exposure
- **Primary CWE**: CWE-200 (Information Exposure)
- **Related**: CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-532 (Insertion of Sensitive Information into Log File), CWE-798 (Use of Hard-coded Credentials)

### crypto-001: Weak Hashing
- **Primary CWE**: CWE-328 (Use of Weak Hash)
- **Related**: CWE-916 (Use of Password Hash With Insufficient Computational Effort)

### crypto-002: Weak Encryption
- **Primary CWE**: CWE-327 (Use of Broken/Risky Cryptographic Algorithm)
- **Related**: CWE-326 (Inadequate Encryption Strength)

### crypto-003: Insecure Randomness
- **Primary CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Related**: CWE-338 (Use of Cryptographically Weak PRNG)

### misconfig-001: Security Misconfiguration
- **Primary CWE**: CWE-16 (Configuration)
- **Related**: CWE-2, CWE-1004, CWE-522

### dependency-001: Vulnerable Dependencies
- **Primary CWE**: CWE-1104 (Use of Unmaintained Third Party Components)
- **Related**: CWE-1035, CWE-937

## Additional CWEs Covered

| CWE ID | Description | Rule ID |
|--------|-------------|---------|
| CWE-20 | Improper Input Validation | * foundational * |
| CWE-94 | Code Injection | codeinjection-001 |
| CWE-117 | Improper Output Neutralization for Logs | infoleak-001 |
| CWE-352 | Cross-Site Request Forgery | csrf-001 |
| CWE-434 | Unrestricted File Upload | fileupload-001 |
| CWE-476 | NULL Pointer Dereference | nullpointer-001 |
| CWE-611 | XXE | xxe-001 |
| CWE-776 | XPath Injection | xpathi-001 |
| CWE-917 | Expression Language Injection | elinjection-001 |

## Notes on Memory Safety Issues

CWEs 787, 416, 125, 119 relate to memory safety issues (buffer overflows, use-after-free). These are primarily relevant for:
- C/C++ codebases
- Rust unsafe blocks
- Java JNI code

For managed languages (Java, JavaScript, Python), these are typically handled by the runtime, but can still occur in:
- Native code interop
- Unsafe deserialization leading to memory corruption
- JVM bugs

## Severity Mapping

| Severity | CVSS Range | Examples |
|----------|------------|----------|
| Critical | 9.0 - 10.0 | SQLi, RCE (Command Injection, Deserialization) |
| High | 7.0 - 8.9 | XSS, Auth bypass, SSRF, Path Traversal |
| Medium | 4.0 - 6.9 | CSRF, Info leakage, Weak crypto |
| Low | 0.1 - 3.9 | Verbose errors, Missing headers |
