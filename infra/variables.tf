variable "aws_region" {
  description = "AWS region to deploy resources"
  default     = "eu-west-1"
}

variable "project" {
  description = "Project name used as prefix for all resources"
  default     = "vuln-alert"
}

variable "env" {
  description = "Environment name"
  default     = "dev"
}

variable "alert_email" {
  description = "Email address to receive CVE alert notifications"
  default     = "your-email@gmail.com"
}

variable "jwt_secret" {
  description = "JWT signing secret for registry service authentication"
  default     = "dev-secret-change-in-production"
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL for CVE alerts"
  default     = "https://hooks.slack.com/services/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"
  sensitive   = true
}
