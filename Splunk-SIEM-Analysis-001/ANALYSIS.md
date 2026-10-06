
# Splunk SIEM Analysis — Internal Audit Logs

| Field | Value |
|-------|-------|
| **Case ID** | Splunk-SIEM-Analysis-001 |
| **Analyst** | Beltus Bejanga |
| **Platform** | Splunk Enterprise (local, `localhost:8000`) |
| **Dataset** | Splunk internal audit logs (SAMPLE) — `internal_audit_logs.Audit` |
| **Scope** | 9,427 events, 24-hour window (2026-09-19 → 2026-09-20) |
| **Goal** | Demonstrate core SIEM workflow: ingest → search → aggregate → interpret |

---

## What this case shows

This is a **skills demonstration on benign sample data**, not a live incident. The aim is to prove I can navigate Splunk, write SPL, build a report, and read the results like an analyst. The same workflow applied to firewall, auth, or EDR logs is how real detections get built.

---

## Step 1 — The search (`02-splunk-search-query.png`)

```spl
| from datamodel:"internal_audit_logs.Audit"
```

This query:
- Accesses the pre-built `internal_audit_logs` data model
- Pulls the `Audit` dataset (admin actions)
- Returns all events matching the time range filter
- Lets Splunk's indexing return the 9,427 matching events in under a second

## Step 2 — What the data contained (`01-splunk-audit-logs.png`)

- **9,427 events** over the last 24 hours, all `sourcetype=audittrail`, host `DESKTOP-IP9FFL3`.
- Each event carries `action`, `host`, `user`, `info`, and a timestamp — the fields you pivot on when hunting.

## Step 3 — Aggregation: top actions (`03-splunk-visualization.png`)

Top values of the `action` field across all 9,427 events (86 distinct actions):

| Action | Count | % |
|--------|------:|----:|
| add | 3,068 | 32.5% |
| list_deployment_server | 731 | 7.8% |
| edit_deployment_server | 720 | 7.6% |
| search | 592 | 6.3% |
| accelerate_search | 270 | 2.9% |
| edit_user | 239 | 2.5% |
| edit_server | 180 | 1.9% |
| edit_forwarders | 135 | 1.4% |
| edit_indexer_cluster | 135 | 1.4% |
| list_forwarders | 135 | 1.4% |

**Analyst reading:** in a real audit log, `edit_user` and `edit_roles` events are exactly what you watch — privilege changes. Here they are routine administrator config activity on a lab instance, but the habit is the point: **in production I would alert on `edit_roles` / `edit_user` by an unexpected account** and pivot on the `user` field to see who did it.

---

## Key SIEM Concepts Applied

| Concept | What We Saw | SOC Relevance |
|---------|------------|---------------|
| Data Ingestion | 9,427 events indexed | SIEM collects from many sources |
| Indexing | Events searchable in <1 second | Enables fast incident response |
| Field Extraction | action, host, user, timestamp fields | Allows targeted threat hunting |
| Aggregation | Top 10 values report | Identifies patterns/anomalies |
| Visualization | Charts and breakdowns | Quick threat assessment |

---

## Skills Demonstrated

✅ Splunk platform navigation  
✅ Data model understanding  
✅ Search query construction  
✅ Report generation and analysis  
✅ Audit log interpretation  
✅ SIEM data analysis workflow  
✅ Threat hunting methodology  

---

## Conclusion

This analysis demonstrates core SIEM competencies required in a SOC:
1. **Data exploration** - Understanding what logs contain
2. **Query construction** - Extracting relevant information
3. **Pattern analysis** - Identifying trends and anomalies
4. **Threat interpretation** - Converting data into security insights

Real SOC analysts perform similar analyses on firewalls, endpoints, network traffic, and authentication logs to detect and respond to security incidents.

---

## Tools & Platforms
- **Splunk Enterprise** - SIEM platform
- **SPL (Splunk Processing Language)** - Query language
- **Pivot & Quick Reports** - Visualization tools

**Investigation Date:** September 20, 2026
