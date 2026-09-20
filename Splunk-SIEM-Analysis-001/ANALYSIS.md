
This query:
- Accesses the pre-built `internal_audit_logs` data model
- Pulls the `Audit` dataset (admin actions)
- Returns all events matching the time range filter
- Indexes data for rapid searching and analysis

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
