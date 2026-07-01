"""
Alert Service - SQS consumer and notification sender
Consumes findings from the SQS queue published by the scanner service
and sends formatted alerts via AWS SNS (email) and optionally Slack.

This service intentionally has no outbound HTTP access except to
AWS APIs and the Slack webhook. The Kubernetes network policy
enforces this restriction — demonstrated in the evaluation chapter.

Author: Sai Siddarth Sandur Kiran Kumar
Student ID: A00336127
MSc Software Design with Cloud Native Computing - TUS Athlone
"""

import boto3
import requests
import os
import json
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# ── AWS clients ──────────────────────────────────────────────
sqs = boto3.client("sqs", region_name=os.environ["AWS_REGION"])
sns = boto3.client("sns", region_name=os.environ["AWS_REGION"])

QUEUE_URL     = os.environ["SQS_QUEUE_URL"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

# Slack webhook is optional — leave blank to disable Slack alerts
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "UNKNOWN":  "⚪"
}


# ── Alert formatters ─────────────────────────────────────────

def format_email_alert(finding: dict) -> dict:
    """Format a finding into a readable email subject and body."""
    severity = finding.get("severity", "UNKNOWN")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")

    subject = (
        f"[{severity}] {finding.get('vuln_id', 'Unknown CVE')} — "
        f"{finding['package']}=={finding['version']}"
    )

    body = f"""
{emoji}  VULNERABILITY ALERT — {severity}
{"=" * 50}

CVE ID:      {finding.get('vuln_id', 'N/A')}
Package:     {finding['package']} {finding['version']}
Ecosystem:   {finding.get('ecosystem', 'Unknown')}
Fix version: {finding.get('fix_version', 'No fix available')}
Detected:    {finding.get('detected_at', 'Unknown')}

What is this vulnerability?
{finding.get('summary', 'No description available')}

How to fix it:
  pip install {finding['package']}=={finding.get('fix_version', 'latest')}

This alert was generated automatically by the Vulnerability Alert
Notification System running on AWS EKS.
    """.strip()

    return {"subject": subject[:100], "body": body}


def format_slack_alert(finding: dict) -> dict:
    """Format a finding as a Slack message with colour coding by severity."""
    severity = finding.get("severity", "UNKNOWN")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")

    colour = {
        "CRITICAL": "#E24B4A",
        "HIGH":     "#EF9F27",
        "MEDIUM":   "#F5C518",
        "LOW":      "#1D9E75"
    }.get(severity, "#888888")

    return {
        "attachments": [{
            "color":  colour,
            "title":  (
                f"{emoji} {severity}: {finding.get('vuln_id')} "
                f"in {finding['package']}=={finding['version']}"
            ),
            "text":   finding.get("summary", ""),
            "fields": [
                {
                    "title": "Fix",
                    "value": (
                        f"`pip install {finding['package']}=="
                        f"{finding.get('fix_version', 'latest')}`"
                    ),
                    "short": True
                },
                {
                    "title": "Detected",
                    "value": finding.get("detected_at", "Unknown"),
                    "short": True
                }
            ],
            "footer": "Vuln Alert System | AWS EKS"
        }]
    }


# ── Notification senders ─────────────────────────────────────

def send_sns_alert(subject: str, body: str):
    """Send alert via AWS SNS — subscribers receive it as an email."""
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=body
        )
        logger.info(f"SNS alert sent: {subject}")
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")


def send_slack_alert(finding: dict):
    """
    Send alert to Slack via incoming webhook.
    Only called for CRITICAL and HIGH findings to avoid notification noise.
    """
    if not SLACK_WEBHOOK:
        logger.debug("Slack webhook not configured — skipping")
        return
    try:
        response = requests.post(
            SLACK_WEBHOOK,
            json=format_slack_alert(finding),
            timeout=5
        )
        response.raise_for_status()
        logger.info("Slack alert sent")
    except Exception as e:
        logger.error(f"Slack webhook failed: {e}")


# ── Message processing ───────────────────────────────────────

def process_finding(message: dict):
    """
    Process a single finding message from SQS.
    Sends SNS email for all severities.
    Sends Slack only for CRITICAL and HIGH to reduce alert noise.
    """
    try:
        finding  = json.loads(message["Body"])
        severity = finding.get("severity", "UNKNOWN")

        logger.info(
            f"Processing [{severity}] {finding.get('vuln_id')} "
            f"for {finding.get('package')}=={finding.get('version')}"
        )

        # Send email via SNS for all findings
        alert = format_email_alert(finding)
        send_sns_alert(alert["subject"], alert["body"])

        # Send Slack only for high severity findings
        if severity in ("CRITICAL", "HIGH"):
            send_slack_alert(finding)

    except json.JSONDecodeError as e:
        logger.error(f"Could not parse message body as JSON: {e}")
    except KeyError as e:
        logger.error(f"Missing expected field in finding: {e}")
    except Exception as e:
        logger.error(f"Unexpected error processing message: {e}")


# ── SQS consumer loop ────────────────────────────────────────

def start_consuming():
    """
    Continuously poll SQS queue for new findings.
    Uses long polling (WaitTimeSeconds=20) to reduce API calls and cost.
    Messages are deleted after successful processing.
    """
    logger.info("Alert service started — polling SQS for findings")
    logger.info(f"Queue: {QUEUE_URL}")

    while True:
        try:
            response = sqs.receive_message(
                QueueUrl=QUEUE_URL,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20    # long polling — cheaper than short polling
            )
            messages = response.get("Messages", [])

            if messages:
                logger.info(f"Received {len(messages)} message(s) from SQS")

            for message in messages:
                process_finding(message)

                # Always delete after processing even if sending failed
                # to prevent the same message being retried indefinitely
                sqs.delete_message(
                    QueueUrl=QUEUE_URL,
                    ReceiptHandle=message["ReceiptHandle"]
                )

        except Exception as e:
            logger.error(f"SQS receive error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    start_consuming()