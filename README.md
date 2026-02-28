# HIPAA Cloud Security: AWS Implementation Guide

A practical, step-by-step guide for implementing HIPAA Security Rule 
technical safeguards in Amazon Web Services. Written specifically for 
healthcare IT teams who need to get compliant, not just get certified.

**Built and maintained by 
[Teknikally Speaking](https://github.com/jesmanderson)** — 
Houston-based cloud security and GRC consultancy specializing in 
healthcare.

---

## The Problem This Repo Solves

HIPAA was written in 1996. AWS did not exist. The regulation tells 
you *what* you need to protect, it does not tell you *how* to protect 
it inside a modern cloud environment.

Most healthcare organizations running on AWS fall into one of two 
categories:

**Category 1:** They have a HIPAA compliance binder full of policies 
with no technical implementation behind any of them. They are 
compliant on paper and exposed in practice.

**Category 2:** Their IT team is technically strong but does not know 
which AWS configurations actually satisfy which HIPAA requirements. 
They are doing good work but cannot prove it to an auditor.

This repo is for both. Every configuration, script, and template here 
maps directly to a specific HIPAA Security Rule requirement so your 
IT team knows exactly what to build and your compliance team knows 
exactly what to document.

---

## How HIPAA Maps to AWS

The HIPAA Security Rule is organized into three safeguard categories. 
This repo covers the Technical Safeguards, the ones that live in 
your infrastructure.

| HIPAA Technical Safeguard | AWS Services That Address It | Repo Section |
|--------------------------|------------------------------|--------------|
| Access Control (§164.312(a)(1)) | IAM, AWS SSO, SCPs | `/iam` |
| Audit Controls (§164.312(b)) | CloudTrail, CloudWatch, Security Hub | `/logging` |
| Integrity (§164.312(c)(1)) | KMS, S3 Object Integrity, AWS Backup | `/encryption` |
| Transmission Security (§164.312(e)(1)) | ACM, TLS enforcement, VPC | `/network` |
| Person Authentication (§164.312(d)) | IAM MFA, AWS SSO, Cognito | `/iam` |
| Contingency Plan (§164.308(a)(7)) | AWS Backup, Route 53, DR configs | `/incident-response` |

---

## Repo Structure
```
HIPAA-Cloud-Security-AWS/
│
├── /iam                  # Access control and person authentication
│   └── ...               # IAM policies, MFA enforcement, least 
│                         # privilege configurations
│
├── /logging              # Audit controls
│   └── ...               # CloudTrail setup, CloudWatch alerts, 
│                         # log retention policies
│
├── /encryption           # Integrity controls
│   └── ...               # KMS configurations, S3 encryption, 
│                         # backup encryption
│
├── /network              # Transmission security
│   └── ...               # VPC configs, TLS enforcement, 
│                         # security group hardening
│
├── /incident-response    # Contingency planning
│   └── ...               # AWS Backup policies, DR runbooks, 
│                         # emergency access procedures
│
├── /templates            # Ready-to-use compliance templates
│   └── ...               # Risk register, gap analysis, 
│                         # evidence collection checklists
│
└── /scripts              # Automation and audit scripts
    └── ...               # PowerShell and AWS CLI scripts for 
                          # auditing, reporting, and remediation
```

---

## Where to Start

If you are new to HIPAA cloud security, start here in this order:

**1. IAM first.** Access control is the foundation of everything else. 
If your IAM environment is not hardened, no other control matters. 
Start with `/iam` and work through every configuration before moving on.

**2. Logging second.** You cannot prove compliance without evidence. 
CloudTrail and CloudWatch are your audit trail. Set these up before 
you need them, after a breach or OCR investigation is too late.

**3. Encryption third.** HIPAA's integrity controls require that ePHI 
is not improperly altered or destroyed. Encryption at rest and in 
transit is an addressable specification, meaning if you do not 
implement it, you need a documented reason why. Most organizations 
should just implement it.

**4. Network fourth.** Transmission security controls how ePHI moves 
between systems. VPC configuration, security groups, and TLS 
enforcement live here.

**5. Incident response last.** You need the other controls in place 
before your contingency plan means anything. But do not skip this, 
HIPAA requires a documented and tested contingency plan.

---

## Who This Is For

**Healthcare IT teams** responsible for cloud infrastructure who need 
to understand what HIPAA actually requires at the technical level, 
not just what the policy document says.

**Security engineers** new to healthcare who have strong AWS skills 
but need to understand how those skills map to regulatory requirements.

**Compliance officers** who need to understand what their IT team is 
building and why each configuration matters for HIPAA.

**Consultants** conducting HIPAA cloud security assessments who want 
a repeatable methodology backed by real configurations.

---

## A Note on HIPAA and AWS Shared Responsibility

AWS is HIPAA eligible, meaning AWS will sign a Business Associate 
Agreement and their infrastructure meets the physical and 
environmental safeguard requirements. But AWS compliance does not 
mean your environment is compliant.

Everything you configure in AWS (IAM, CloudTrail, encryption, 
network controls) is your responsibility. This repo covers your 
side of the shared responsibility model.

---

## Repo Status

This repo is actively being built. Current status:

| Section | Status |
|---------|--------|
| `/iam` | 🔄 In progress |
| `/logging` | 🔲 Coming next |
| `/encryption` | 🔲 Planned |
| `/network` | 🔲 Planned |
| `/incident-response` | 🔲 Planned |
| `/templates` | 🔲 Planned |
| `/scripts` | 🔲 Planned |

Follow 
for updates as new sections are published.

---

## Contributing

Found an error, a better configuration, or a missing HIPAA 
requirement? Open an issue or submit a pull request. This repo 
is meant to be a living resource, real-world healthcare 
environments are messy and edge cases matter.

---

## Disclaimer

This repo is for educational and implementation guidance purposes. 
It does not constitute legal advice and does not guarantee HIPAA 
compliance. Every healthcare organization's environment is different. 
Use this as a starting point and validate configurations against your 
specific environment, BAAs, and compliance obligations.

---

## About Teknikally Speaking

Teknikally Speaking is a Houston-based cybersecurity consultancy 
specializing in cloud security and GRC for healthcare organizations. 
We help healthcare IT teams implement HIPAA-aligned cloud security 
controls — hands-on technical work, not just policy documents.

If your organization needs a HIPAA Cloud Security Assessment or 
hands-on implementation support, reach out through LinkedIn.

**Services:** HIPAA Cloud Security Assessments · AWS IAM Governance · 
Cloud Security Posture Management · GRC Advisory · vCISO

[LinkedIn](https://linkedin.com/company/teknikally-speaking) | 
[Substack](#) | [GitHub](https://github.com/jesmanderson)
