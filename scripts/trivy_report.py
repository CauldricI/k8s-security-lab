#!/usr/bin/env python3
import argparse, json, sys
import pandas as pd

def parse_args():
    ap = argparse.ArgumentParser(description="Summarize Trivy JSON into a CSV")
    ap.add_argument("--input", required=True, help="Path to trivy JSON (trivy --format json -o file.json)")
    ap.add_argument("--out", default="report.csv", help="Output CSV path")
    ap.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS to include (e.g., 7.0)")
    return ap.parse_args()

def main():
    args = parse_args()
    with open(args.input, "r") as f:
        data = json.load(f)

    rows = []
    results = data.get("Results", []) if isinstance(data, dict) else []
    for res in results:
        vulns = res.get("Vulnerabilities", []) or []
        target = res.get("Target")
        for v in vulns:
            cvss = 0.0
            # Trivy may present multiple vendor scores; prefer NVD if present
            if "CVSS" in v and isinstance(v["CVSS"], dict):
                nvd = v["CVSS"].get("nvd") or v["CVSS"].get("V3Score")  # fallback legacy
                if isinstance(nvd, dict):
                    cvss = float(nvd.get("V3Score") or nvd.get("V2Score") or 0.0)
                elif isinstance(nvd, (int, float, str)):
                    try:
                        cvss = float(nvd)
                    except:  # noqa
                        cvss = 0.0
            elif v.get("CVSS", 0):
                try:
                    cvss = float(v["CVSS"])
                except:  # noqa
                    cvss = 0.0

            if cvss < args.min_cvss:
                continue

            rows.append({
                "Target": target,
                "Severity": v.get("Severity"),
                "CVE": v.get("VulnerabilityID"),
                "Package": v.get("PkgName"),
                "InstalledVersion": v.get("InstalledVersion"),
                "FixedVersion": v.get("FixedVersion"),
                "Title": v.get("Title"),
                "CVSS": cvss,
                "PrimaryURL": v.get("PrimaryURL"),
            })

    if not rows:
        print("No findings at/above threshold; writing empty report.")
        pd.DataFrame([]).to_csv(args.out, index=False)
        sys.exit(0)

    df = pd.DataFrame(rows).sort_values(["Severity", "CVSS"], ascending=[True, False])
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} findings → {args.out}")

if __name__ == "__main__":
    main()
