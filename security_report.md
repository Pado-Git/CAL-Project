# CAL Security Assessment Report

**Target:** http://localhost:8888
**Generated:** Sun, 11 Jan 2026 13:24:17 KST
**Engaged Targets:** 1
**Vulnerability Candidates:** 4
**Verified Vulnerabilities:** 3

## Attack Targets
The following targets were identified and subjected to active security testing:
- `http://localhost:8888`

## Executive Summary
**Found 4 vulnerability candidate(s)** pending verification:

- PathTraversal: 1 candidate(s)
- XSS: 1 candidate(s)
- SQLi: 2 candidate(s)

**Confirmed 3 verified vulnerabilit(ies)**:

| Severity | Type | URL | Payload |
|---|---|---|---|
| **High** | CommandInjection | `http://localhost:8888/cmd` | `whoami` |
| **High** | SQLi | `http://localhost:8888/login` | `' OR '1'='1 --` |
| **High** | SQLi-TimeBased | `http://host.docker.internal:8888/sqli` | `1' AND SLEEP(5)-- -` |

## Vulnerability Candidates (Pending Verification)
The following potential vulnerabilities were identified and are awaiting active verification:

| Type | URL | Parameter | Status |
|---|---|---|---|
| SQLi | `http://localhost:8888/login` | `` | pending |
| SQLi | `http://host.docker.internal:8888/sqli` | `id` | pending |
| PathTraversal | `http://localhost:8888/path` | `` | pending |
| XSS | `http://host.docker.internal:8888/xss` | `search` | pending |

## Verified Vulnerabilities (Exploited)
### 1. CommandInjection
- **Severity:** High
- **URL:** `http://localhost:8888/cmd`
- **Payload:** `whoami`
- **Timestamp:** Sun, 11 Jan 2026 13:23:19 KST
- **Description:**
Verified CommandInjection vulnerability. 
Evidence: Command execution confirmed with payload: whoami (parameter: command)

### 2. SQLi
- **Severity:** High
- **URL:** `http://localhost:8888/login`
- **Payload:** `' OR '1'='1 --`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

### 3. SQLi-TimeBased
- **Severity:** High
- **URL:** `http://host.docker.internal:8888/sqli`
- **Payload:** `1' AND SLEEP(5)-- -`
- **Timestamp:** Sun, 11 Jan 2026 13:24:17 KST
- **Description:**
Verified SQLi-TimeBased vulnerability. 
Evidence: Time-based Blind SQLi confirmed with payload: 1' AND SLEEP(5)-- -

