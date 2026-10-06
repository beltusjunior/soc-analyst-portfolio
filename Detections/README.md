# Detections

Detection content derived from the investigations in this portfolio. The point
of a SOC analyst is not only to investigate a threat once, but to turn each
investigation into a repeatable detection. Every rule here maps back to a case.

## Splunk (SPL)

| File | Detects | From case |
|------|---------|-----------|
| [`splunk/brute_force_auth.spl`](splunk/brute_force_auth.spl) | Many auth failures then a success from one source (SSH + Windows RDP) | IP-Investigation-001, Network-Traffic-Analysis-001 |
| [`splunk/ioc_sweep.spl`](splunk/ioc_sweep.spl) | Any portfolio IOC (IPs, C2, phishing domain, hash, kworker masquerade) across all logs | All cases |

## Sigma (portable, convert with `sigma convert` / `pySigma`)

| File | Detects | ATT&CK |
|------|---------|--------|
| [`sigma/ssh_bruteforce_then_success.yml`](sigma/ssh_bruteforce_then_success.yml) | SSH brute force leading to a successful login | T1110.001 |
| [`sigma/linux_kworker_masquerade.yml`](sigma/linux_kworker_masquerade.yml) | Process masquerading as a `[kworker/...]` kernel thread | T1036.004 |
| [`sigma/phishing_replit_domain.yml`](sigma/phishing_replit_domain.yml) | Access to the verified phishing domain + lookalike pattern | T1566.002 |

## Indicators of Compromise

A consolidated, machine-readable list of every indicator across all cases is in
[`iocs.csv`](iocs.csv).

> These rules are written as a starting point. Thresholds and field names must
> be tuned to the target environment before production use — see the notes in
> each file.
