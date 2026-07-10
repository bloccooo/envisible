# Reports

Investigation reports (security audits, performance analyses, bug postmortems) and their fix-tracking checklists.

## Convention

- Each investigation is a standalone `*_REPORT.md` — the narrative: symptoms, root cause, evidence, proposed fixes.
- Fixes are tracked as checkboxes:
  - Large audits get a paired `*_TODO.md` (e.g. `SECURITY_REPORT.md` → `SECURITY_TODO.md`) since they contain many independent findings.
  - Small, single-incident reports track fixes inline in a `## Fix tracking` section near the top of the report itself.
- A report links to its checklist via a `**Fix tracking:**` line in its header (or vice versa).
- When a fix lands, check the box and add a one-line note (what changed / where / test added). Don't delete the report — it's the record of *why*.
- New reports: add a row below and follow the same pattern.

## Index

| Report | Fix tracking | Status |
|---|---|---|
| [SECURITY_REPORT.md](./SECURITY_REPORT.md) | [SECURITY_TODO.md](./SECURITY_TODO.md) | Open — no items fixed yet |
| [PERFORMANCE_REPORT.md](./PERFORMANCE_REPORT.md) | [PERFORMANCE_TODO.md](./PERFORMANCE_TODO.md) | Partially fixed — compaction (Issue 2) implemented |
| [LOGIN_FAILURE_REPORT.md](./LOGIN_FAILURE_REPORT.md) | inline `## Fix tracking` section | Partially fixed — root cause (Fix 1) fixed and tested |
