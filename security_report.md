# CAL Security Assessment Report

**Target:** http://localhost:8888
**Generated:** Sun, 11 Jan 2026 01:14:29 KST
**Engaged Targets:** 1
**Vulnerability Candidates:** 4
**Verified Vulnerabilities:** 3

## Attack Targets
The following targets were identified and subjected to active security testing:
- `http://localhost:8888`

## Executive Summary
**Found 4 vulnerability candidate(s)** pending verification:

- SQLi: 2 candidate(s)
- XSS: 1 candidate(s)
- PathTraversal: 1 candidate(s)

**Confirmed 3 verified vulnerabilit(ies)**:

| Severity | Type | URL | Payload |
|---|---|---|---|
| **High** | CommandInjection | `http://localhost:8888/cmd` | `& whoami` |
| **High** | SQLi | `http://localhost:8888/login` | `' OR '1'='1` |
| **High** | SQLi | `http://host.docker.internal:8888/sqli` | `1 OR 1=1` |

## Vulnerability Candidates (Pending Verification)
The following potential vulnerabilities were identified and are awaiting active verification:

| Type | URL | Parameter | Status |
|---|---|---|---|
| SQLi | `http://localhost:8888/login` | `` | pending |
| SQLi | `http://localhost:8888/sqli` | ``id`` | pending |
| XSS | `http://localhost:8888/xss` | `search` | pending |
| PathTraversal | `http://localhost:8888/path` | ``file`` | pending |

## Verified Vulnerabilities (Exploited)
### 1. CommandInjection
- **Severity:** High
- **URL:** `http://localhost:8888/cmd`
- **Payload:** `& whoami`
- **Timestamp:** Sun, 11 Jan 2026 01:13:35 KST
- **Description:**
Verified CommandInjection vulnerability. 
Evidence: Command execution confirmed with payload: & whoami (parameter: command)

### 2. SQLi
- **Severity:** High
- **URL:** `http://localhost:8888/login`
- **Payload:** `' OR '1'='1`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

### 3. SQLi
- **Severity:** High
- **URL:** `http://host.docker.internal:8888/sqli`
- **Payload:** `1 OR 1=1`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

