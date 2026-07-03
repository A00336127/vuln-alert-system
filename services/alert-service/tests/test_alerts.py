"""
Unit tests for the alert service.
"""
import os
from unittest.mock import patch

os.environ["AWS_REGION"]     = "eu-west-1"
os.environ["SQS_QUEUE_URL"]  = "https://sqs.eu-west-1.amazonaws.com/123/test"
os.environ["SNS_TOPIC_ARN"]  = "arn:aws:sns:eu-west-1:123:test"

with patch("boto3.client"):
    from main import format_email_alert, format_slack_alert

SAMPLE_FINDING = {
    "vuln_id":    "GHSA-test-1234",
    "package":    "django",
    "version":    "4.2.0",
    "ecosystem":  "PyPI",
    "severity":   "CRITICAL",
    "fix_version": "4.2.16",
    "summary":    "SQL injection vulnerability",
    "detected_at": "2026-07-01T10:00:00Z"
}


def test_email_subject_contains_severity():
    alert = format_email_alert(SAMPLE_FINDING)
    assert "CRITICAL" in alert["subject"]


def test_email_subject_contains_package():
    alert = format_email_alert(SAMPLE_FINDING)
    assert "django" in alert["subject"]


def test_email_body_contains_fix_version():
    alert = format_email_alert(SAMPLE_FINDING)
    assert "4.2.16" in alert["body"]


def test_slack_message_has_attachments():
    slack = format_slack_alert(SAMPLE_FINDING)
    assert "attachments" in slack
    assert len(slack["attachments"]) > 0


def test_slack_critical_is_red():
    slack = format_slack_alert(SAMPLE_FINDING)
    assert slack["attachments"][0]["color"] == "#E24B4A"
