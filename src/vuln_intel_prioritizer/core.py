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


def load_vulns(path: str | Path) -> list[Vulnerability]:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        Vulnerability(
            cve=row["cve"],
            cvss=float(row["cvss"]),
            exploited=bool(row["exploited"]),
            internet_exposed=bool(row["internet_exposed"]),
            asset_criticality=row["asset_criticality"],
            affected_asset=row["affected_asset"],
            summary=row["summary"],
        )
        for row in rows
    ]


def prioritize(vulns: list[Vulnerability]) -> list[dict[str, object]]:
    return sorted((_rank(vuln) for vuln in vulns), key=lambda item: item["priority_score"], reverse=True)


def write_report(items: list[dict[str, object]], path: str | Path) -> None:
    rows = "\n".join(
        f"| {item['priority_score']} | {item['sla']} | {item['cve']} | {item['affected_asset']} | {item['reason']} |"
        for item in items
    )
    Path(path).write_text(
        f"""# Vulnerability Prioritization Report

| Priority | SLA | CVE | Asset | Reason |
| --- | --- | --- | --- | --- |
{rows}
""",
        encoding="utf-8",
    )


def _rank(vuln: Vulnerability) -> dict[str, object]:
    score = int(vuln.cvss * 7)
    reasons = [f"CVSS {vuln.cvss}"]
    if vuln.exploited:
        score += 25
        reasons.append("known exploited")
    if vuln.internet_exposed:
        score += 15
        reasons.append("internet exposed")
    if vuln.asset_criticality == "critical":
        score += 15
        reasons.append("critical asset")
    elif vuln.asset_criticality == "high":
        score += 8
        reasons.append("high-value asset")
    score = min(score, 100)
    return {
        "cve": vuln.cve,
        "affected_asset": vuln.affected_asset,
        "priority_score": score,
        "sla": _sla(score),
        "reason": ", ".join(reasons),
        "summary": vuln.summary,
    }


def _sla(score: int) -> str:
    if score >= 90:
        return "Patch or mitigate within 24 hours"
    if score >= 75:
        return "Patch within 72 hours"
    if score >= 50:
        return "Patch within 14 days"
    return "Track in normal patch cycle"
