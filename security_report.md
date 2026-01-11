# CAL Security Assessment Report

**Target:** http://localhost:8888
**Generated:** Mon, 12 Jan 2026 02:28:46 KST
**Engaged Targets:** 6
**Compromised Targets:** 1
**Vulnerability Candidates:** 4
**Verified Vulnerabilities:** 3

## Attack Targets
The following targets were identified and subjected to active security testing:
- `http://localhost:8888`
- `http://localhost:8888/xss`
- `http://localhost:8888/login`
- `http://localhost:8888/path`
- `http://localhost:8888/sqli`
- `http://localhost:8888/cmd`

## 💀 Compromised Targets (Shell Obtained)
The following targets have been fully compromised with agent deployment:

| Target URL | Agent PAW | Platform | Host | User | Privilege |
|---|---|---|---|---|---|
| `http://localhost:8888/cmd` | `cyxwec` | linux | 3b1df54d56f1 | root | **Elevated** |

## Executive Summary
**Found 4 vulnerability candidate(s)** pending verification:

- SQLi: 2 candidate(s)
- PathTraversal: 1 candidate(s)
- XSS: 1 candidate(s)

**Confirmed 3 verified vulnerabilit(ies)**:

| Severity | Type | URL | Payload |
|---|---|---|---|
| **High** | CommandInjection | `http://localhost:8888/cmd` | `whoami` |
| **High** | SQLi | `http://localhost:8888/sqli` | `' OR '1'='1` |
| **High** | SQLi | `http://localhost:8888/login` | `' OR '1'='1` |

## Vulnerability Candidates (Pending Verification)
The following potential vulnerabilities were identified and are awaiting active verification:

| Type | URL | Parameter | Status |
|---|---|---|---|
| SQLi | `http://localhost:8888/sqli` | `id` | pending |
| SQLi | `http://localhost:8888/login` | `username` | pending |
| PathTraversal | `http://localhost:8888/path` | `file` | pending |
| XSS | `http://localhost:8888/xss` | `search` | pending |

## Verified Vulnerabilities (Exploited)
### 1. CommandInjection
- **Severity:** High
- **URL:** `http://localhost:8888/cmd`
- **Payload:** `whoami`
- **Timestamp:** Mon, 12 Jan 2026 02:26:42 KST
- **Description:**
Verified CommandInjection vulnerability. 
Evidence: Command execution confirmed with payload: whoami (parameter: command)

### 2. SQLi
- **Severity:** High
- **URL:** `http://localhost:8888/sqli`
- **Payload:** `' OR '1'='1`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

### 3. SQLi
- **Severity:** High
- **URL:** `http://localhost:8888/login`
- **Payload:** `' OR '1'='1`
- **Timestamp:** 
- **Description:**
Verified SQLi vulnerability. 
Error/Output: 

