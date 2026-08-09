"""
Scanner Service - CVE scanning background worker
Queries the OSV.dev API every 30 minutes to check registered packages
for known vulnerabilities and publishes NEW findings to SQS for the
alert service.

Extended with:
- EPSS exploit-probability scoring (FIRST.org)
- Git commit provenance (traces each finding to the commit/author
  that introduced the vulnerable package version)
- Duplicate-alert prevention — a finding only triggers a
  notification the first time it's seen; subsequent scans update
  last_seen_at silently without re-alerting

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
from github import Github

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# ── AWS clients ──────────────────────────────────────────────
# All credentials come from IRSA in EKS, or mounted local credentials
# in Docker Compose. The scanner role has permission to: read
# DynamoDB stacks, read/write findings, publish to SQS, write to S3.
dynamodb       = boto3.resource("dynamodb", region_name=os.environ["AWS_REGION"])
sqs            = boto3.client("sqs",        region_name=os.environ["AWS_REGION"])
s3_client      = boto3.client("s3",         region_name=os.environ["AWS_REGION"])

stacks_table   = dynamodb.Table(os.environ["STACKS_TABLE"])
findings_table = dynamodb.Table(os.environ["FINDINGS_TABLE"])

QUEUE_URL  = os.environ["SQS_QUEUE_URL"]
S3_BUCKET  = os.environ["S3_BUCKET"]
OSV_API    = "https://api.osv.dev/v1"
EPSS_API   = "https://api.first.org/data/v1/epss"

# GitHub client for commit provenance lookups.
# GITHUB_TOKEN is optional — if not set, provenance is skipped
# gracefully and every finding just gets an empty provenance dict.
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
gh_client = Github(GITHUB_TOKEN) if GITHUB_TOKEN else None


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

    return "HIGH"


def get_fix_version(vuln: dict, package: str) -> str:
    """
    Extract the patched version from OSV data.
    Handles both clean 'fixed' events and the messier 'last_affected'
    case where OSV has no confirmed upper-bound fix — a real gap in
    the OSV schema that a naive implementation silently mishandles.
    """
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for version_range in affected.get("ranges", []):
            events = version_range.get("events", [])
            fixed = [e["fixed"] for e in events if "fixed" in e]
            if fixed:
                return fixed[-1]
            last_affected = [e["last_affected"] for e in events if "last_affected" in e]
            if last_affected:
                return f"unknown (last confirmed vulnerable: {last_affected[-1]})"
    return "No fix information available"


# ── EPSS exploit-probability scoring ─────────────────────────

def extract_cve_id(vuln: dict):
    """
    EPSS only understands CVE IDs, but OSV.dev often returns
    GHSA-style IDs as the primary identifier. Check the 'aliases'
    field for a CVE alias before giving up — some advisories
    genuinely have no CVE assigned and that's an expected outcome,
    not an error.
    """
    if vuln.get("id", "").startswith("CVE-"):
        return vuln["id"]
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return None


def get_epss_score(cve_id) -> dict:
    """
    Queries FIRST.org's EPSS API for the probability this CVE
    will be exploited in the wild in the next 30 days.
    Free, public, no API key required.
    """
    if not cve_id:
        return {"epss_score": None, "epss_percentile": None}
    try:
        response = requests.get(EPSS_API, params={"cve": cve_id}, timeout=5)
        response.raise_for_status()
        data = response.json().get("data", [])
        if data:
            return {
                "epss_score":      float(data[0]["epss"]),
                "epss_percentile": float(data[0]["percentile"])
            }
    except requests.RequestException as e:
        logger.error(f"EPSS lookup failed for {cve_id}: {e}")
    return {"epss_score": None, "epss_percentile": None}


# ── Git commit provenance ────────────────────────────────────

def find_introducing_commit(github_repo: str, file_path: str, package: str) -> dict:
    """
    Uses GitHub's commit history to find the commit that introduced
    the current version of a package into a dependency file.
    Returns an empty dict if GitHub isn't configured, the stack has
    no repo/path metadata, or nothing is found — provenance is a
    bonus, never a blocker for the core scan.
    """
    if not gh_client or not github_repo or not file_path:
        return {}
    try:
        repo = gh_client.get_repo(github_repo)
        commits = repo.get_commits(path=file_path)
        for commit in commits:
            for f in commit.files:
                if f.filename == file_path and package in (f.patch or ""):
                    return {
                        "commit_sha":   commit.sha[:7],
                        "author":       commit.commit.author.name,
                        "author_email": commit.commit.author.email,
                        "date":         commit.commit.author.date.isoformat(),
                        "message":      commit.commit.message.split("\n")[0],
                        "commit_url":   commit.html_url,
                    }
    except Exception as e:
        logger.error(f"Provenance lookup failed for {package} in {github_repo}: {e}")
    return {}


# ── Duplicate-alert prevention ───────────────────────────────

def is_new_finding(finding_id: str) -> bool:
    """
    Checks if this exact finding (user + vuln ID combination) has
    already been recorded in a previous scan. Prevents re-alerting
    on every 30-minute cycle for a CVE that was already found and
    reported — the underlying stack still gets rescanned every
    cycle (that's the whole point of continuous monitoring), but
    the notification only fires once per genuinely new finding.
    """
    response = findings_table.get_item(Key={"finding_id": finding_id})
    return "Item" not in response


# ── S3 data lake writer ──────────────────────────────────────

def write_finding_to_s3(finding: dict):
    """
    Write finding to S3 data lake partitioned by year and month.
    Written on every scan cycle (not just new findings) so that
    last_seen_at stays current for Athena historical queries.
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
    queries OSV.dev for each, enriches with EPSS and commit
    provenance, and publishes only NEW critical/high findings to
    SQS. Every stack is rescanned every cycle regardless of
    whether it produced findings before — that continuous
    rescanning is what closes the temporal exposure gap discussed
    in Chapter 2. Only the ALERTING is deduplicated, not the scan.
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
    new_findings   = 0
    known_findings = 0

    for stack in stacks:
        package     = stack["package"]
        version     = stack["version"]
        ecosystem   = stack["ecosystem"]
        user_id     = stack["user_id"]
        github_repo = stack.get("github_repo", "")   # optional metadata
        file_path   = stack.get("file_path", "")      # optional metadata

        vulns = query_osv(package, version, ecosystem)

        for vuln in vulns:
            vuln_id    = vuln.get("id", "UNKNOWN")
            finding_id = f"{user_id}#{vuln_id}"
            severity   = get_severity(vuln)
            fix        = get_fix_version(vuln, package)

            # Check BEFORE overwriting the record, so we know
            # whether this is genuinely new or already seen
            first_seen = is_new_finding(finding_id)

            cve_id     = extract_cve_id(vuln)
            epss       = get_epss_score(cve_id)
            provenance = find_introducing_commit(github_repo, file_path, package)

            now_iso = datetime.now(timezone.utc).isoformat()

            finding = {
                "finding_id":      finding_id,
                "user_id":         user_id,
                "finding_type":    "CVE",
                "vuln_id":         vuln_id,
                "cve_id":          cve_id,
                "package":         package,
                "version":         version,
                "ecosystem":       ecosystem,
                "severity":        severity,
                "fix_version":     fix,
                "summary":         vuln.get("summary", "No description available"),
                "detected_at":     now_iso,   # overwritten each scan; see note below
                "last_seen_at":    now_iso,
                "epss_score":      epss["epss_score"],
                "epss_percentile": epss["epss_percentile"],
                "introduced_by":   provenance,   # {} if unavailable
            }

            # Preserve the ORIGINAL detected_at on repeat sightings —
            # only set it fresh the first time this finding is seen.
            if not first_seen:
                existing = findings_table.get_item(Key={"finding_id": finding_id}).get("Item", {})
                finding["detected_at"] = existing.get("detected_at", now_iso)

            # Always write/update — keeps last_seen_at current for
            # Athena queries and lets us later detect when a finding
            # disappears (i.e. was fixed) by comparing timestamps.
            findings_table.put_item(Item=finding)
            write_finding_to_s3(finding)

            if severity in ("CRITICAL", "HIGH"):
                if first_seen:
                    sqs.send_message(
                        QueueUrl=QUEUE_URL,
                        MessageBody=json.dumps(finding, default=str)
                    )
                    epss_pct = (
                        f"{epss['epss_score']*100:.1f}%"
                        if epss["epss_score"] is not None else "N/A"
                    )
                    logger.warning(
                        f"[NEW] [{severity}] {vuln_id} — {package}=={version} — "
                        f"fix: {fix} — EPSS: {epss_pct}"
                    )
                    new_findings += 1
                else:
                    logger.info(
                        f"[KNOWN] {vuln_id} — {package}=={version} — "
                        f"already alerted, updating last_seen_at only"
                    )
                    known_findings += 1

    logger.info(
        f"Scan complete — {new_findings} new finding(s) alerted, "
        f"{known_findings} known finding(s) refreshed"
    )


# ── Scheduler ────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Scanner service starting")
    logger.info("Running initial scan on startup...")

    run_cve_scan()

    # Tightened from hourly to every 30 minutes, bounding new-CVE
    # detection latency to a much sharper worst case for evaluation.
    schedule.every(30).minutes.do(run_cve_scan)
    logger.info("Scheduler active — scanning every 30 minutes")

    while True:
        schedule.run_pending()
        time.sleep(30)