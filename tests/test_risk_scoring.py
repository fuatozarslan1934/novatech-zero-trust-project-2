from ztlab.risk_scoring import calculate_risk_score


def test_risk_score():
    findings = [
        {"severity": "high"},
        {"severity": "medium"},
    ]

    assert calculate_risk_score(findings) == 45


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