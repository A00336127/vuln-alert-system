"""
Unit tests for the scanner service.
"""
import os
from unittest.mock import patch

os.environ["AWS_REGION"]     = "eu-west-1"
os.environ["STACKS_TABLE"]   = "test-stacks"
os.environ["FINDINGS_TABLE"] = "test-findings"
os.environ["SQS_QUEUE_URL"]  = "https://sqs.eu-west-1.amazonaws.com/123/test"
os.environ["S3_BUCKET"]      = "test-bucket"

with patch("boto3.resource"), patch("boto3.client"):
    from main import get_severity, get_fix_version, query_osv


def test_severity_critical():
    assert get_severity({"severity": [{"type": "CVSS_V3", "score": "9.5"}]}) == "CRITICAL"


def test_severity_high():
    assert get_severity({"severity": [{"type": "CVSS_V3", "score": "7.5"}]}) == "HIGH"


def test_severity_unknown_when_empty():
    assert get_severity({}) == "UNKNOWN"


def test_get_fix_version_found():
    vuln = {
        "affected": [{
            "package": {"name": "django"},
            "ranges": [{
                "events": [
                    {"introduced": "4.2.0"},
                    {"fixed": "4.2.16"}
                ]
            }]
        }]
    }
    assert get_fix_version(vuln, "django") == "4.2.16"


def test_get_fix_version_not_found():
    assert get_fix_version({}, "django") == "No fix available yet"


def test_query_osv_live():
    """
    Live integration test — confirms OSV.dev returns CVEs for
    a known vulnerable version. Requires internet connection.
    """
    vulns = query_osv("django", "4.2.0", "PyPI")
    assert len(vulns) > 0, "Expected CVEs for django==4.2.0"
