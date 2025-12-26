---

## 🔹 `WORKFLOW.md`

```markdown
# OSINT Workflow Engine

## Automated Decision Flow

1. Input normalization
2. Passive OSINT collection
3. Safe active OSINT
4. Pivot discovery
5. Risk scoring (0–100)
6. Workflow decision:
   - LOW → minimal
   - MEDIUM → limited pivots
   - HIGH → full pivots
7. Evidence stored (SQLite + JSON)

Designed for SOC and Red Team usage.
