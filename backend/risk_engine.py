def calculate_risk(findings, typosquatting_findings):
    """
    Calculate an overall software supply-chain risk score.

    Score range: 0 to 100.
    Higher score = higher risk.
    """

    score = 0

    # ---------------------------------------
    # Vulnerability findings
    # ---------------------------------------

    for finding in findings:

        severity = str(
            finding.get("severity", "")
        ).upper()

        if severity == "CRITICAL":
            score += 40

        elif severity == "HIGH":
            score += 30

        elif severity == "MEDIUM":
            score += 20

        elif severity == "LOW":
            score += 5

        elif severity == "UNKNOWN":
            score += 10

    # ---------------------------------------
    # Typosquatting findings
    # ---------------------------------------

    for finding in typosquatting_findings:

        severity = str(
            finding.get("severity", "")
        ).upper()

        if severity == "HIGH":
            score += 30

        elif severity == "MEDIUM":
            score += 20

        else:
            score += 10

    # ---------------------------------------
    # Keep score between 0 and 100
    # ---------------------------------------

    score = min(score, 100)

    # ---------------------------------------
    # Risk level
    # ---------------------------------------

    if score >= 80:
        risk_level = "CRITICAL"

    elif score >= 60:
        risk_level = "HIGH"

    elif score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return score, risk_level