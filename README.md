# Project 2 — Zero Trust & Cloud Identity Attack-Path Analyzer

**Student project | No Azure subscription required | Python + simulated hybrid-cloud exports**

## Your role

You are a Cloud Security Engineer at fictional **NovaTech**. Following an access-governance review, your manager has delivered a collection of exported Azure RBAC assignments, Entra users/groups, privileged access assignments, Conditional Access policies, workloads, networking rules, and sign-in activity. Your assignment is to **develop an offline Python tool** that can answer: *Who has access to what, how did they get that access, which controls apply, and where could several weaknesses combine to create material risk?*

This is **not** Project 1 again. Project 1 focused on parsing individual logs and generating incident reports. Here your primary deliverable is **effective-permission analysis, Zero Trust what-if evaluation, and identity-to-resource attack-path mapping**. Events and network logs provide secondary evidence.

Do not create Azure resources. Work exclusively with the fictional files under `data/`.

## What you need to build

Use Python to develop a CLI with these target commands (you design the implementation):

```bash
python run.py validate-data
python run.py inventory
python run.py access --principal u-001
python run.py access --resource vm-portal-edge-01
python run.py privileged
python run.py policy-check --user u-008 --app 'Azure DevOps' --source-ip 198.51.100.89 --mfa false --compliant false
python run.py attack-paths
python run.py explain-path --path-id PATH-001
python run.py compare-controls --baseline baseline --proposed docs/proposed_controls.json
python run.py report --format html
```

Only `validate-data` is implemented as a baseline convenience command. **The rest are your assignments**, and should exit with a clear *not implemented* message until you implement them. Your output format may vary as long as results are machine-readable and documented.

## First-time setup (macOS / Linux)

```bash
git init  # Only if this is a new local project, not if cloned from an existing repository
python3 --version  # Python 3.11+ recommended
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py validate-data
python -m pytest -q
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py validate-data
python -m pytest -q
```

Do not upload `.env`, real credentials, or local machine secrets. The lab core should run **offline**, even when an AI API is not configured. Use source control and meaningful commits. Include command screenshots in the final README.

## Optional Claude Code / Codex setup

If you already use **Claude Code** or **Codex CLI**, launch it from this repository to help build and review code. Follow each provider's official installation/authentication instructions; CLI access and API billing are not necessarily the same thing. You do **not** need either product to complete the lab. Alternatively, build an optional `ai_explainer.py` provider using the supported OpenAI or Anthropic Python SDK and keys in a local `.env` file.

Recommended workflow for any AI-assisted code: ask for a plan, write a small function, add tests, inspect its logic, run the tests, then commit. Put your tool/model usage and examples of fixes you personally verified in `docs/DEVELOPMENT_NOTES.md`. Never give AI permission to upload these datasets to a public external service by default; the data are synthetic but your pipeline must still demonstrate secret handling.

## Project phases

### Phase 1 — Data ingestion and normalization

Read **all** JSON and CSV inputs. Validate required fields, duplicate IDs, missing references, timestamps, and schema inconsistencies. Store normalized entities using your own classes/dataclasses or Pydantic. Keep the raw evidence intact for auditability. Document any incomplete records rather than silently omitting them.

Deliverable: `inventory` command, data-quality report, unit tests.

### Phase 2 — Effective Azure RBAC permissions

Implement access evaluation for direct users, groups, nested groups, service principals, and managed identities. Roles at subscription scope apply to resources underneath; resource-group roles apply only within their groups; resource-specific roles must not magically apply elsewhere. Aggregate additive role assignments and identify the **exact assignment chain** granting each effective permission.

Use `data/azure/role_capability_map.json` only as a **simplified training mapping**. In production, actual role actions/dataActions, NotActions, assignment conditions, and deny assignments need richer evaluation. Clearly label model limitations. Never conflate Azure RBAC with Entra directory roles or with network connectivity.

Deliverable: `access` and `privileged` commands, traceable permission paths and tests for inherited/group permissions.

### Phase 3 — PIM and privilege lifecycle

Distinguish **active**, **eligible**, and **expired** PIM records at the snapshot time. An eligible assignment is not effective without activation. An expired activation is not current effective access. Flag unnecessary standing access, stale users with powerful active roles, credential expiration risk, and overly broad service-principal privileges. Do not automatically classify every Owner assignment as unauthorized or every break-glass exception as wrong: explain business context and missing evidence.

Deliverable: least-privilege recommendations with supporting assignment IDs and tests.

### Phase 4 — Simplified Conditional Access What-If

Create an explicit, **training-only** evaluator for the policy JSON: enabled vs. report-only vs. disabled; user/group include and exclude lists; target apps; trusted/untrusted locations; legacy-client block; MFA; compliant device. Report *applicable enforced policies*, *report-only findings*, *unmet controls*, and the final result in your own documented simplified model.

This is **not** a reproduction of Microsoft's production Conditional Access engine. Treat exclusions thoughtfully, especially designated emergency access accounts; identify policy coverage gaps without claiming an exclusion is always inappropriate. Conditional Access sign-in controls do not inherently remove an Azure role assignment.

Deliverable: `policy-check`, 8+ policy unit tests, coverage report for privileged users.

### Phase 5 — Network context

Ingest the ordered NSG and normalized Cisco ACL rules, resources' zones and interfaces, and network flow telemetry. Ask which potential communications are permitted under your **documented approximation** of the synthetic rules. Do not assume reaching a port means achieving login, code execution, or access to data. Clearly separate confirmed connectivity, potential access, and speculative post-compromise behavior.

Deliverable: reachability assessment for administrative ports and sensitive data zones.

### Phase 6 — Attack-path graph

Build a directed graph relating principals, group membership, role assignments, scope, resource ownership, managed identities, and potential network routes. Enumerate risky **conditional** chains using the evidence, e.g. *untrusted network -> reachable workload -> assumed workload compromise -> attached identity -> sensitive secret-reader access*. Mark every transition with `observed`, `configured`, or `hypothetical` and provide references to exact source rows/rules.

Design your algorithm to discover paths based on general relationships. **Do not hardcode any known user ID, IP, VM, incident, or expected outcome.** Explain potential paths without implementing actual compromise/exploitation.

Deliverable: `attack-paths`, `explain-path`, JSON graph export, diagram.

### Phase 7 — Control comparison & report

Write a proposed control plan in `docs/proposed_controls.json` that changes a few simulated rules, group memberships, role assignments, or policy states. Run the baseline and proposed environments, compare effective access and detected risks, and produce an HTML or Markdown executive report with evidence, business impact, least-privilege recommendations, and trade-offs. Evaluate potential **lockout** and legitimate break-glass recovery issues rather than recommending indiscriminate blocking.

Deliverable: readable before/after report plus test results.

### Phase 8 — Independent validation

Create at least **20 unit tests**, including new datasets that you create independently, not only assertions against the supplied records. Tests should cover scope inheritance, transitive groups, PIM state, exclusions, report-only policies, conflicting NSG priorities, false positives, unknown user IDs, and ambiguous timestamp evidence.

A reviewer will test your software with a **second unseen dataset**. It must run against another directory using `--data-dir` or a documented config variable **without changes to your source code**.

## Deliverable checklist

- [ ] Reproducible setup on your own PC (CLI + virtual environment)
- [ ] Dynamic inventory & schema validation
- [ ] Effective permissions with reasoned provenance
- [ ] PIM active vs eligible vs expired states
- [ ] Simplified Conditional Access What-If with explicit limitations
- [ ] Ordered NSG and Cisco rule evaluation
- [ ] Conditional attack-path graph with evidence and assumptions
- [ ] Proposed mitigation and before/after comparison
- [ ] 20+ meaningful automated tests + GitHub Actions
- [ ] Markdown or HTML management report and technical evidence appendix
- [ ] Updated GitHub README, development notes, and demo screenshots

## Questions you must be able to answer in an interview

What is effective permission vs. assigned role? Why does scope inheritance matter? How do nested groups change a permission analysis? Why isn't PIM eligibility equal to active access? What's the difference between Conditional Access and Azure RBAC? Can you prove a network route enables exfiltration? What assumptions are required? Why might a risky-looking exclusion be legitimate? How would you avoid locking administrators out? What did you personally code, test, and debug with or without AI?

## Dataset reference

See `data/schema/data_dictionary.json`. All files are synthetic, use documentation-only external IP ranges, and contain **no real secrets**. Treat the snapshot date in the exports as the analysis reference time. Cisco-style syslog lines intentionally omit the year: the dataset year is 2026; assume UTC for this simulation and document that limitation.

## Primary technical reading

- [Azure RBAC scope and inheritance](https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview)
- [Azure RBAC role assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments)
- [PIM Azure role activation](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-activate-your-roles)
- [Conditional Access report-only mode](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only)
