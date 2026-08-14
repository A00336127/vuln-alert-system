# Vulnerability Alert Notification System

A cloud-native DevSecOps pipeline demonstrating automated security controls at build, deploy, and runtime stages on AWS EKS — built as an MSc final project.

**Design and Implementation of a Secure Cloud-Native Deployment Pipeline Using GitOps, Kubernetes, and Automated Security Controls on AWS**

Sai Siddarth Sandur Kiran Kumar · A00336127
MSc Software Design with Cloud Native Computing · TUS Athlone
Supervisor: Amit Hirway

---

## Overview

Software vulnerabilities are published faster than most organisations can track them — 40,289 CVEs in 2024 alone, with 23.6% weaponised on the day of disclosure (CISA, 2024). Build-time scanning alone leaves a temporal gap: a package clean at build time can become vulnerable months later, with nothing re-checking it (the Log4Shell pattern).

This project closes that gap two ways:

1. **A four-stage DevSecOps pipeline** — build-time scanning (Trivy, pip-audit, Bandit), IaC scanning (tfsec, Checkov), admission control (Kyverno), and runtime threat detection (Falco) — deployed via GitOps (ArgoCD).
2. **A Vulnerability Alert Notification System** — three Python microservices that continuously monitor registered packages against the OSV.dev CVE database and alert in real time, demonstrating the pipeline on a realistic workload.

Unlike detect-only tools (SonarQube, Snyk, NeuVector, AccuKnox), this project integrates detection **and** GitOps deployment in one pipeline, using a single consistent vulnerability data source (OSV.dev) across both build-time and runtime checks.

## Architecture

```
Developer → GitHub → GitHub Actions (Trivy/pip-audit/Bandit) → ECR → ArgoCD
                                                                        |
                                          AWS EKS Cluster               v
        +-----------------------------------------------------------+
        |  Kyverno (admission) . Falco (runtime) . NetworkPolicies  |
        |  Registry service . Scanner service . Alert service       |
        +-----------------------------------------------------------+
                                        |
                                        v
        DynamoDB . SQS . SNS . Secrets Manager . S3 data lake
                                        |
                                        v
                    OSV.dev API <- Scanner <- Falco monitors this call
```

Scanner's outbound call to OSV.dev is the key runtime security story: Falco monitors it, and network policy restricts Scanner to that destination only.

## Services

| Service | Responsibility |
|---|---|
| **Registry** | FastAPI REST API — user auth (JWT) and package registration (`POST /stacks`) |
| **Scanner** | Background worker — queries OSV.dev every 10 minutes for registered packages, scores findings with EPSS (exploit probability), traces each finding to its introducing Git commit, deduplicates repeat alerts |
| **Alert** | SQS consumer — delivers formatted alerts via SNS email and Slack for CRITICAL/HIGH findings |

### What makes the Scanner distinctive
- **EPSS scoring** — attaches real-world exploitation probability (FIRST.org) to every finding, not just CVSS severity
- **Commit provenance** — traces each vulnerable package back to the exact Git commit and author that introduced it
- **Duplicate-alert prevention** — rescans every cycle (continuous monitoring) but only notifies on genuinely new findings

## Tech Stack

| Layer | Tools |
|---|---|
| Application | Python 3.12, FastAPI, boto3, PyGithub |
| Infrastructure | Terraform (VPC, EKS, DynamoDB, SQS, SNS, S3, Secrets Manager, ECR) |
| CI | GitHub Actions, Trivy, pip-audit, Bandit |
| Deployment | Helm, ArgoCD (GitOps) |
| Security | Kyverno (admission), Falco (runtime), Kubernetes NetworkPolicies, IRSA (per-service least-privilege IAM) |
| Vulnerability data | OSV.dev (CVE), FIRST.org (EPSS) |

## Repository Structure

```
services/
  registry-service/   FastAPI app, JWT auth, DynamoDB
  scanner-service/    OSV.dev + EPSS + provenance worker
  alert-service/      SQS consumer -> SNS/Slack
infra/                Terraform (VPC, EKS, ECR, DynamoDB, SQS, SNS, S3)
k8s/
  charts/              Helm charts (one per service)
  argocd/               ArgoCD Application manifests
  policies/             Kyverno, NetworkPolicy, Falco custom rules
.github/workflows/ci.yaml  Build, scan, push to ECR
docker-compose.yaml         Local development
```

## Local Development

```bash
cp .env.example .env   # fill in AWS account ID, JWT secret, GitHub token, Slack webhook
docker compose up --build
curl http://localhost:8001/health
```

## Cloud Deployment (AWS EKS)

```bash
cd infra
terraform init && terraform apply

aws eks update-kubeconfig --region eu-west-1 --name vuln-alert-eks

helm install <service> k8s/charts/<service>
kubectl apply -f k8s/argocd/
```

Each service runs under its own scoped IRSA role (least-privilege IAM per pod, not a shared node role) — see `infra/main.tf`.

## Evaluation

Measured against: CVEs blocked at build time (Trivy), IaC issues caught (tfsec/Checkov), Kyverno policy violations blocked, Falco mean-time-to-detect, deployment frequency (ArgoCD), CVE detection latency, and historical exposure-window analysis. Full results in the project report, Chapter 5.

## Known Limitations

- External Secrets Operator is configured but did not persist through an AWS account plan closure/reactivation event; Kubernetes Secrets are currently created manually as a documented fallback
- Package monitoring requires explicit registration (no automatic dependency discovery from a repository)
- Manifest-based dependency resolution (not lock-file-based) — see Chapter 6 for the accuracy tradeoff this implies

## Future Work

- Automated fix PRs and closed-loop remediation verification
- Cloud misconfiguration scanning (boto3-based CIS benchmark checks)
- LLM-assisted CVE explanation via AWS Bedrock
- Automatic repository-wide dependency discovery

## Links

- Repository: https://github.com/A00336127/vuln-alert-system
- OSV.dev: https://osv.dev
- EPSS: https://www.first.org/epss/
