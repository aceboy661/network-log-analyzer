# Investigation Report - Network Log Analyzer

**Date:** October 28, 2026  
**Analyst:** Marlon Lonmon  
**Project:** Network Log Analyzer

---

## Summary
The suspicious connection detector was run against sample network/firewall logs. Suspicious activity was identified.

---

## Findings

### 1. Connections to Unusual Ports
- Detected connections involving ports **4444** and **12345**
- These ports are commonly associated with malware, backdoors, and remote access tools

**Severity:** High

### 2. Repeated Connection Attempts
- Multiple connection attempts were observed from the same source IP in a short time window
- This pattern can indicate scanning or brute-force activity

**Severity:** Medium

---

## Recommendation
- Investigate the source IPs
- Consider blocking unusual ports at the firewall
- Correlate with host-based logs for further context

---

## Conclusion
The script successfully identified suspicious network activity. This project demonstrates practical network log analysis skills useful for SOC and Junior Cybersecurity roles.
