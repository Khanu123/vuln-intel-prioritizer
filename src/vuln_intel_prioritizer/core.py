from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Vulnerability:
    cve: str
    cvss: float
    exploited: bool
    internet_exposed: bool
    asset_criticality: str
    affected_asset: str
    summary: str
    epss: float = 0.0
    kev_listed: bool = False
    public_exploit: bool = False
    fix_available: bool = True
    compensating_control: bool = False
    days_open: int = 0
    data_source: str = "synthetic"


def load_vulns(path: str | Path) -> list[Vulnerability]:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("Vulnerability input must be a JSON array.")
    vulns = [
        Vulnerability(
            cve=row["cve"],
            cvss=float(row["cvss"]),
            exploited=bool(row["exploited"]),
            internet_exposed=bool(row["internet_exposed"]),
            asset_criticality=row["asset_criticality"],
            affected_asset=row["affected_asset"],
            summary=row["summary"],
            epss=float(row.get("epss", 0.0)),
            kev_listed=bool(row.get("kev_listed", row.get("exploited", False))),
            public_exploit=bool(row.get("public_exploit", False)),
            fix_available=bool(row.get("fix_available", True)),
            compensating_control=bool(row.get("compensating_control", False)),
            days_open=int(row.get("days_open", 0)),
            data_source=str(row.get("data_source", "synthetic")),
        )
        for row in rows
    ]
    for vuln in vulns:
        if not 0 <= vuln.cvss <= 10:
            raise ValueError(f"{vuln.cve}: CVSS must be between 0 and 10.")
        if not 0 <= vuln.epss <= 1:
            raise ValueError(f"{vuln.cve}: EPSS must be between 0 and 1.")
        if vuln.asset_criticality not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"{vuln.cve}: unsupported asset criticality {vuln.asset_criticality}.")
    return vulns


def prioritize(vulns: list[Vulnerability]) -> list[dict[str, object]]:
    return sorted((_rank(vuln) for vuln in vulns), key=lambda item: item["priority_score"], reverse=True)


def write_report(items: list[dict[str, object]], path: str | Path) -> None:
    rows = "\n".join(
        f"| {item['priority_score']} | {item['sla']} | {item['cve']} | {item['affected_asset']} | {item['reason']} | {item['data_source']} |"
        for item in items
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        f"""# Vulnerability Prioritization Report

| Priority | SLA | CVE | Asset | Reason | Source |
| --- | --- | --- | --- | --- | --- |
{rows}
""",
        encoding="utf-8",
    )


def write_json(items: list[dict[str, object]], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(items, indent=2), encoding="utf-8")


def _rank(vuln: Vulnerability) -> dict[str, object]:
    breakdown: dict[str, int] = {"cvss": int(vuln.cvss * 4)}
    score = breakdown["cvss"]
    reasons = [f"CVSS {vuln.cvss}"]
    if vuln.kev_listed or vuln.exploited:
        breakdown["known_exploitation"] = 25
        score += 25
        reasons.append("known exploited/KEV")
    epss_points = round(vuln.epss * 15)
    if epss_points:
        breakdown["epss"] = epss_points
        score += epss_points
        reasons.append(f"EPSS {vuln.epss:.1%}")
    if vuln.public_exploit:
        breakdown["public_exploit"] = 10
        score += 10
        reasons.append("public exploit")
    if vuln.internet_exposed:
        breakdown["internet_exposure"] = 10
        score += 10
        reasons.append("internet exposed")
    if vuln.asset_criticality == "critical":
        breakdown["asset_criticality"] = 10
        score += 10
        reasons.append("critical asset")
    elif vuln.asset_criticality == "high":
        breakdown["asset_criticality"] = 6
        score += 6
        reasons.append("high-value asset")
    if vuln.days_open >= 30:
        breakdown["age"] = 5
        score += 5
        reasons.append(f"open {vuln.days_open} days")
    if vuln.compensating_control:
        breakdown["compensating_control"] = -10
        score -= 10
        reasons.append("compensating control")
    score = max(0, min(score, 100))
    return {
        "cve": vuln.cve,
        "affected_asset": vuln.affected_asset,
        "priority_score": score,
        "sla": _sla(score),
        "reason": ", ".join(reasons),
        "summary": vuln.summary,
        "score_breakdown": breakdown,
        "fix_available": vuln.fix_available,
        "recommended_action": "Patch" if vuln.fix_available else "Mitigate and monitor until a vendor fix is available",
        "data_source": vuln.data_source,
    }


def _sla(score: int) -> str:
    if score >= 90:
        return "Patch or mitigate within 24 hours"
    if score >= 75:
        return "Patch within 72 hours"
    if score >= 50:
        return "Patch within 14 days"
    return "Track in normal patch cycle"
