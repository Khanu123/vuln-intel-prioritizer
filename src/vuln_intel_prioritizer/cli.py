from __future__ import annotations

import argparse
from pathlib import Path

from .core import load_vulns, prioritize, write_json, write_report


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description="Prioritize vulnerabilities by exploitability and business risk.")
    parser.add_argument("--vulns", default=str(ROOT / "sample_data" / "vulnerabilities.json"))
    parser.add_argument("--out", default="vulnerability_priorities.md")
    parser.add_argument("--json", default="vulnerability_priorities.json")
    args = parser.parse_args()

    ranked = prioritize(load_vulns(args.vulns))
    write_report(ranked, args.out)
    write_json(ranked, args.json)
    print(f"Prioritized {len(ranked)} vulnerabilities.")
    print(f"Top priority: {ranked[0]['cve']} ({ranked[0]['priority_score']})")
    print(f"Report: {args.out}")
    print(f"JSON: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
