terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── DynamoDB Tables ──────────────────────────────────────────

resource "aws_dynamodb_table" "stacks" {
  name         = "${var.project}-stacks-${var.env}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_id"
  range_key    = "stack_id"

  attribute {
    name = "user_id"
    type = "S"
  }
  attribute {
    name = "stack_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.tags
}

resource "aws_dynamodb_table" "findings" {
  name         = "${var.project}-findings-${var.env}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.tags
}

resource "aws_dynamodb_table" "users" {
  name         = "${var.project}-users-${var.env}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "username"

  attribute {
    name = "username"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.tags
}

# ── SQS Queue + Dead Letter Queue ────────────────────────────

resource "aws_sqs_queue" "findings_dlq" {
  name                      = "${var.project}-findings-dlq-${var.env}"
  message_retention_seconds = 1209600  # 14 days
  tags                      = local.tags
}

resource "aws_sqs_queue" "findings" {
  name                       = "${var.project}-findings-${var.env}"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 86400   # 1 day

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.findings_dlq.arn
    maxReceiveCount     = 3
  })

  tags = local.tags
}

# ── SNS Topic ────────────────────────────────────────────────

resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts-${var.env}"
  tags = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── S3 Buckets ───────────────────────────────────────────────

resource "aws_s3_bucket" "findings" {
  bucket = "${var.project}-findings-${data.aws_caller_identity.current.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "findings" {
  bucket = aws_s3_bucket.findings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  bucket                  = aws_s3_bucket.findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Secrets Manager ──────────────────────────────────────────

resource "aws_secretsmanager_secret" "slack_webhook" {
  name        = "${var.project}/slack-webhook/${var.env}"
  description = "Slack incoming webhook URL for CVE alerts"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "slack_webhook" {
  secret_id     = aws_secretsmanager_secret.slack_webhook.id
  secret_string = var.slack_webhook_url
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name        = "${var.project}/jwt-secret/${var.env}"
  description = "JWT signing key for registry service"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = var.jwt_secret
}

# ── Data sources ─────────────────────────────────────────────

data "aws_caller_identity" "current" {}

# ── Locals ───────────────────────────────────────────────────

locals {
  tags = {
    Project     = var.project
    Environment = var.env
    ManagedBy   = "terraform"
  }
}

# ── Outputs ──────────────────────────────────────────────────

output "stacks_table_name" {
  value = aws_dynamodb_table.stacks.name
}

output "findings_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "users_table_name" {
  value = aws_dynamodb_table.users.name
}

output "sqs_queue_url" {
  value = aws_sqs_queue.findings.url
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.findings.bucket
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "slack_webhook_secret_arn" {
  value = aws_secretsmanager_secret.slack_webhook.arn
}