#!/usr/bin/env python3
"""Fetch sample CVEs for testing."""

import json
import time
from datetime import datetime
from pathlib import Path

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves_by_id_range(start_num: int, end_num: int, year: int = 2024, max_results: int = 1000) -> list[dict]:
    """Fetch CVEs by querying specific CVE IDs."""
    cves = []

    print(f"Fetching CVE-{year}-{start_num:04d} through CVE-{year}-{end_num:04d}...")

    with httpx.Client(timeout=60.0) as client:
        current_num = start_num
        consecutive_misses = 0

        while len(cves) < max_results and current_num <= end_num:
            cve_id = f"CVE-{year}-{current_num}"

            if current_num % 100 == 0:
                print(f"  Checking {cve_id}... ({len(cves)} found so far)")

            try:
                response = client.get(NVD_API_URL, params={"cveId": cve_id})

                if response.status_code == 404:
                    consecutive_misses += 1
                    current_num += 1
                    continue

                response.raise_for_status()
                data = response.json()

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    print("  Rate limited. Waiting 30 seconds...")
                    time.sleep(30)
                    continue
                current_num += 1
                continue
            except httpx.RequestError as e:
                print(f"  Request error: {e}")
                current_num += 1
                continue

            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                consecutive_misses = 0
                cve_data = vulnerabilities[0].get("cve", {})

                cve_entry = {
                    "cve_id": cve_data.get("id", ""),
                    "published": cve_data.get("published", ""),
                    "description": "",
                    "severity": "",
                    "cvss_score": None,
                }

                for desc in cve_data.get("descriptions", []):
                    if desc.get("lang") == "en":
                        cve_entry["description"] = desc.get("value", "")[:200]
                        break

                metrics = cve_data.get("metrics", {})
                for cvss_key in ["cvssMetricV31", "cvssMetricV30"]:
                    if cvss_key in metrics and metrics[cvss_key]:
                        cvss_data = metrics[cvss_key][0].get("cvssData", {})
                        cve_entry["severity"] = cvss_data.get("baseSeverity", "")
                        cve_entry["cvss_score"] = cvss_data.get("baseScore")
                        break

                cves.append(cve_entry)
            else:
                consecutive_misses += 1

            current_num += 1

            # Rate limiting - be conservative
            time.sleep(0.5)

    return cves


def fetch_recent_cves(max_results: int = 1000, start_from: int = 0) -> list[dict]:
    """Fetch CVEs using pagination, optionally starting from a specific index."""
    cves = []
    start_index = start_from
    results_per_page = 200

    print(f"Fetching {max_results} recent CVEs...")

    with httpx.Client(timeout=60.0) as client:
        while len(cves) < max_results:
            params = {
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }

            print(f"  Fetching batch starting at index {start_index}...")

            try:
                response = client.get(NVD_API_URL, params=params)
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPStatusError as e:
                print(f"  Error: HTTP {e.response.status_code}")
                if e.response.status_code == 403:
                    print("  Rate limited. Waiting 30 seconds...")
                    time.sleep(30)
                    continue
                raise
            except httpx.RequestError as e:
                print(f"  Request error: {e}")
                raise

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print("  No more results.")
                break

            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")

                cve_entry = {
                    "cve_id": cve_id,
                    "published": cve_data.get("published", ""),
                    "description": "",
                    "severity": "",
                    "cvss_score": None,
                }

                for desc in cve_data.get("descriptions", []):
                    if desc.get("lang") == "en":
                        cve_entry["description"] = desc.get("value", "")[:200]
                        break

                metrics = cve_data.get("metrics", {})
                for cvss_key in ["cvssMetricV31", "cvssMetricV30"]:
                    if cvss_key in metrics and metrics[cvss_key]:
                        cvss_data = metrics[cvss_key][0].get("cvssData", {})
                        cve_entry["severity"] = cvss_data.get("baseSeverity", "")
                        cve_entry["cvss_score"] = cvss_data.get("baseScore")
                        break

                cves.append(cve_entry)

                if len(cves) >= max_results:
                    break

            total_results = data.get("totalResults", 0)
            print(f"  Got {len(vulnerabilities)} CVEs. Total collected: {len(cves)}. API total: {total_results}")

            start_index += results_per_page

            if start_index >= total_results or len(cves) >= max_results:
                break

            # Rate limit
            print("  Waiting 6 seconds (rate limit)...")
            time.sleep(6)

    return cves[:max_results]


def main():
    # Fetch 1000 CVEs starting from near the end to get recent ones
    # Total is ~330,000 so start at 320,000 to get recent CVEs
    cves = fetch_recent_cves(max_results=1000, start_from=320000)

    # Save to file
    output_dir = Path(__file__).parent.parent / "tests" / "data"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "sample_cves.json"

    with open(output_file, "w") as f:
        json.dump(
            {
                "fetched_at": datetime.now().isoformat(),
                "count": len(cves),
                "cves": cves,
            },
            f,
            indent=2,
        )

    print(f"\nSaved {len(cves)} CVEs to {output_file}")

    # Also save just the CVE IDs for quick reference
    ids_file = output_dir / "sample_cve_ids.txt"
    with open(ids_file, "w") as f:
        for cve in cves:
            f.write(cve["cve_id"] + "\n")

    print(f"Saved CVE IDs to {ids_file}")

    # Print summary by year
    years = {}
    for cve in cves:
        cve_id = cve.get("cve_id", "")
        if cve_id.startswith("CVE-"):
            year = cve_id.split("-")[1]
            years[year] = years.get(year, 0) + 1

    print("\nYear distribution:")
    for year, count in sorted(years.items(), reverse=True):
        print(f"  {year}: {count}")

    # Severity distribution
    severities = {}
    for cve in cves:
        sev = cve.get("severity") or "UNKNOWN"
        severities[sev] = severities.get(sev, 0) + 1

    print("\nSeverity distribution:")
    for sev, count in sorted(severities.items()):
        print(f"  {sev}: {count}")


if __name__ == "__main__":
    main()
