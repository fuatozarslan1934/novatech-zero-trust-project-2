RISK_WEIGHTS = {
    "high": 30,
    "medium": 15,
    "low": 5,
}


def calculate_risk_score(findings):
    scores = {}

    for index, finding in enumerate(findings):
        assignment_ids = finding.get("assignment_ids", [])
        broad = finding.get("type") in {
            "broad_service_principal_access",
            "broad_standing_role_review",
        }

        if broad and assignment_ids:
            key = ("assignment", tuple(sorted(assignment_ids)))
        else:
            key = ("finding", index)

        score = RISK_WEIGHTS.get(finding["severity"], 0)
        scores[key] = max(scores.get(key, 0), score)

    return min(sum(scores.values()), 100)

    def test_duplicate_rbac_findings():
        findings = [
        {
            "type": "broad_service_principal_access",
            "severity": "high",
            "assignment_ids": ["ra-022"],
        },
        {
            "type": "broad_standing_role_review",
            "severity": "medium",
            "assignment_ids": ["ra-022"],
        },
        {
            "type": "credential_expired",
            "severity": "high",
            "assignment_ids": [],
        },
    ]

    assert calculate_risk_score(findings) == 60
