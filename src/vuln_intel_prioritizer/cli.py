from __future__ import annotations

import argparse
from pathlib import Path

from .core import load_vulns, prioritize, write_report


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description="Prioritize vulnerabilities by exploitability and business risk.")
    parser.add_argument("--vulns", default=str(ROOT / "sample_data" / "vulnerabilities.json"))
    parser.add_argument("--out", default="vulnerability_priorities.md")
    args = parser.parse_args()

    ranked = prioritize(load_vulns(args.vulns))
    write_report(ranked, args.out)
    print(f"Prioritized {len(ranked)} vulnerabilities.")
    print(f"Top priority: {ranked[0]['cve']} ({ranked[0]['priority_score']})")
    print(f"Report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
