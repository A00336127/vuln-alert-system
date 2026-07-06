"""
Scanner Service - CVE scanning background worker
Queries the OSV.dev API hourly to check registered packages for new
vulnerabilities and publishes findings to SQS for the alert service.

OSV.dev is chosen because it is free, requires no authentication,
and uses the same data source as Trivy in the CI pipeline —
ensuring consistent vulnerability data across build-time and
runtime detection stages.

Author: Sai Siddarth Sandur Kiran Kumar
Student ID: A00336127
MSc Software Design with Cloud Native Computing - TUS Athlone
"""

import boto3
import requests
import os
import json
import logging
import schedule
import time
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# ── AWS clients ──────────────────────────────────────────────
# All credentials come from IRSA. The scanner role has permission to:
# read DynamoDB stacks, write findings, publish to SQS, write to S3.
dynamodb       = boto3.resource("dynamodb", region_name=os.environ["AWS_REGION"])
sqs            = boto3.client("sqs",        region_name=os.environ["AWS_REGION"])
s3_client      = boto3.client("s3",         region_name=os.environ["AWS_REGION"])

stacks_table   = dynamodb.Table(os.environ["STACKS_TABLE"])
findings_table = dynamodb.Table(os.environ["FINDINGS_TABLE"])

QUEUE_URL  = os.environ["SQS_QUEUE_URL"]
S3_BUCKET  = os.environ["S3_BUCKET"]
OSV_API    = "https://api.osv.dev/v1"


# ── OSV.dev helpers ──────────────────────────────────────────

def query_osv(package: str, version: str, ecosystem: str) -> list:
    """
    Call OSV.dev API to get all known vulnerabilities for a specific
    package version.

    Note: This makes an outbound HTTP call to api.osv.dev.
    Falco monitors this call and network policies restrict outbound
    access to this domain only — demonstrated in the evaluation chapter.
    """
    try:
        response = requests.post(
            f"{OSV_API}/query",
            json={
                "version": version,
                "package": {
                    "name":      package,
                    "ecosystem": ecosystem
                }
            },
            timeout=10
        )
        response.raise_for_status()
        vulns = response.json().get("vulns", [])
        logger.info(f"OSV.dev returned {len(vulns)} vulns for {package}=={version}")
        return vulns

    except requests.Timeout:
        logger.error(f"OSV.dev timed out for {package}=={version}")
        return []
    except requests.RequestException as e:
        logger.error(f"OSV.dev API error for {package}: {e}")
        return []


def get_severity(vuln: dict) -> str:
    """
    Determine severity from OSV vulnerability data.
    OSV does not always include a numeric CVSS score directly,
    so we parse the severity type and fall back to HIGH if unclear.
    """
    severities = vuln.get("severity", [])
    if not severities:
        return "UNKNOWN"

    for sev in severities:
        sev_type = sev.get("type", "")
        if "CVSS_V3" in sev_type or "CVSS_V4" in sev_type:
            try:
                score = float(sev.get("score", 0))
                if score >= 9.0: return "CRITICAL"
                if score >= 7.0: return "HIGH"
                if score >= 4.0: return "MEDIUM"
                return "LOW"
            except (ValueError, TypeError):
                pass

    # Default to HIGH if severity field exists but score is unparseable
    return "HIGH"


def get_fix_version(vuln: dict, package: str) -> str:
    """Extract the patched version from OSV data if available."""
    for affected in vuln.get("affected", []):
        pkg_name = affected.get("package", {}).get("name", "").lower()
        if pkg_name == package.lower():
            for version_range in affected.get("ranges", []):
                for event in version_range.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return "No fix available yet"


def write_finding_to_s3(finding: dict):
    """
    Write finding to S3 data lake partitioned by year and month.
    This allows AWS Glue to crawl efficiently and Athena to use
    partition pruning for faster historical queries.
    """
    now    = datetime.utcnow()
    s3_key = (
        f"findings/"
        f"year={now.year}/"
        f"month={now.month:02d}/"
        f"{finding['finding_id'].replace('#', '_')}.json"
    )
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=json.dumps(finding, default=str),
            ContentType="application/json"
        )
    except Exception as e:
        # Log but do not fail the scan — S3 is for analytics,
        # DynamoDB is the primary store
        logger.error(f"S3 write failed for {s3_key}: {e}")


# ── Main scan logic ──────────────────────────────────────────

def run_cve_scan():
    """
    Main CVE scan. Reads all registered stacks from DynamoDB,
    queries OSV.dev for each, and publishes critical findings to SQS.
    Runs on startup and then every hour via the scheduler.
    """
    logger.info("=" * 50)
    logger.info("Starting CVE scan")
    logger.info("=" * 50)

    response = stacks_table.scan()
    stacks   = response.get("Items", [])

    if not stacks:
        logger.info("No stacks registered yet — nothing to scan")
        return

    logger.info(f"Scanning {len(stacks)} registered package(s)")
    total_findings = 0

    for stack in stacks:
        package   = stack["package"]
        version   = stack["version"]
        ecosystem = stack["ecosystem"]
        user_id   = stack["user_id"]

        vulns = query_osv(package, version, ecosystem)

        for vuln in vulns:
            vuln_id  = vuln.get("id", "UNKNOWN")
            severity = get_severity(vuln)
            fix      = get_fix_version(vuln, package)

            finding = {
                "finding_id":   f"{user_id}#{vuln_id}",
                "user_id":      user_id,
                "finding_type": "CVE",
                "vuln_id":      vuln_id,
                "package":      package,
                "version":      version,
                "ecosystem":    ecosystem,
                "severity":     severity,
                "fix_version":  fix,
                "summary":      vuln.get("summary", "No description available"),
                "detected_at":  datetime.now(timezone.utc).isoformat()
            }

            # Write to DynamoDB — primary store for the API
            findings_table.put_item(Item=finding)

            # Write to S3 — for Athena historical trend analysis
            write_finding_to_s3(finding)

            # Only alert on CRITICAL and HIGH to avoid alert fatigue
            if severity in ("CRITICAL", "HIGH"):
                sqs.send_message(
                    QueueUrl=QUEUE_URL,
                    MessageBody=json.dumps(finding)
                )
                logger.warning(
                    f"[{severity}] {vuln_id} — "
                    f"{package}=={version} — fix: {fix}"
                )
                total_findings += 1

    logger.info(
        f"Scan complete — {total_findings} critical/high findings sent to alert queue"
    )


# ── Scheduler ────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Scanner service starting")
    logger.info("Running initial scan on startup...")

    run_cve_scan()

    # Schedule hourly scans.
    # Note: A Kubernetes CronJob would be more idiomatic but the
    # schedule library keeps this prototype simple and self-contained.
    schedule.every(1).hours.do(run_cve_scan)
    logger.info("Scheduler active — scanning every hour")

    while True:
        schedule.run_pending()
        time.sleep(60)