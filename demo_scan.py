"""
R7 Quickstart Interactive Scan Runner
Usage: python demo_scan.py [domain]
"""

import sys
import time

# Ensure Windows stdout handles UTF-8 safely
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from storage.db import init_db, get_db_session, create_tenant, create_scan_job, get_scan_job, get_ai_report_for_job, get_findings_for_job
from worker import execute_pipeline_for_job


def run_demo(target_domain: str = "scanme.nmap.org"):
    print("=" * 70)
    print("   [+] R7 (RECONNAISSANCE 7) -- RED TEAM RECON PLATFORM")
    print("=" * 70)
    print(f"[*] Target Domain : {target_domain}")
    print(f"[*] Database      : SQLite (local file: recon7.db)")
    print(f"[*] Initializing schema...")
    
    init_db()

    with get_db_session() as db:
        # Create demo tenant
        tenant = create_tenant(db, "Red Team Alpha Ops")
        job = create_scan_job(db, tenant_id=tenant.id, target_domain=target_domain)
        tenant_id = tenant.id
        job_id = job.id

    print(f"[*] Provisioned Tenant ID : {tenant_id}")
    print(f"[*] Created Scan Job ID    : {job_id}")
    print("\n[+] Launching 10-Stage Reconnaissance Pipeline...\n")

    start_time = time.time()
    success = execute_pipeline_for_job(job_id=job_id, tenant_id=tenant_id, target_domain=target_domain)
    duration = time.time() - start_time

    print("\n" + "=" * 70)
    if success:
        print(f"[+] Scan Job Finished Successfully in {duration:.1f}s!")
        print("=" * 70 + "\n")

        with get_db_session() as db:
            findings = get_findings_for_job(db, tenant_id=tenant_id, scan_job_id=job_id)
            report = get_ai_report_for_job(db, tenant_id=tenant_id, scan_job_id=job_id)

            print(f"[*] Summary of Findings ({len(findings)} total):")
            type_counts = {}
            for f in findings:
                type_counts[f.type] = type_counts.get(f.type, 0) + 1
            for ftype, count in type_counts.items():
                print(f"   * {ftype.ljust(16)}: {count} findings")

            if report:
                print("\n" + "=" * 70)
                print("[*] GENERATED AI ENGAGEMENT REPORT (Preview):")
                print("=" * 70 + "\n")
                preview_lines = report.report_text.splitlines()[:35]
                print("\n".join(preview_lines))
                if len(report.report_text.splitlines()) > 35:
                    print("\n... [Remaining report stored in SQLite database] ...")
    else:
        print("[-] Scan Job Failed. Check log output above for details.")
        print("=" * 70)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    run_demo(target)
