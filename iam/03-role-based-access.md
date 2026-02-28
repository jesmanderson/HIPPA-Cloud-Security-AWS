# Role-Based Access: IAM Roles for Healthcare Cloud Environments

## HIPAA Requirement

HIPAA's Access Control standard (§164.312(a)(1)) requires unique 
user identification and role-based access controls that limit each 
user to only the ePHI and AWS resources their job function requires.

In AWS, IAM roles are the right way to implement this. Direct 
IAM user permissions are harder to audit, harder to revoke, and 
harder to govern at scale. Roles with clearly defined trust 
policies and permission scopes are the HIPAA-aligned approach.

---

## Core Role Architecture for Healthcare AWS Environments

These four roles cover the majority of access patterns in a 
healthcare cloud environment. Customize resource ARNs for your 
specific account and bucket names.

---

### Role 1 — HealthcareAdmin

**Who uses it:** Cloud administrators who manage the AWS environment.
**HIPAA principle:** Admin access should be tightly controlled, 
require MFA, and be used only when administrative tasks are needed, 
not for routine operations.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMFAForAdminAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    },
    {
      "Sid": "AllowAdministrativeActions",
      "Effect": "Allow",
      "Action": [
        "iam:*",
        "ec2:*",
        "s3:*",
        "rds:*",
        "cloudtrail:*",
        "cloudwatch:*",
        "kms:*",
        "logs:*"
      ],
      "Resource": "*"
    }
  ]
}
```

> This role denies all access without MFA, admin actions on 
> ePHI environments must always require MFA authentication.

---

### Role 2 — HealthcareAuditor

**Who uses it:** Compliance officers, security analysts, auditors 
conducting HIPAA assessments.
**HIPAA principle:** Auditors need visibility but zero ability to 
modify resources or access ePHI content. Read-only access to 
configuration and logs only.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadOnlyAccess",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "cloudtrail:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "cloudwatch:Describe*",
        "logs:Get*",
        "logs:List*",
        "logs:Describe*",
        "logs:FilterLogEvents",
        "s3:ListBucket",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "config:Get*",
        "config:List*",
        "config:Describe*",
        "securityhub:Get*",
        "securityhub:List*",
        "securityhub:Describe*",
        "guardduty:Get*",
        "guardduty:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyEPhIDataAccess",
      "Effect": "Deny",
      "Action": [
        "s3:GetObject",
        "rds:*",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ],
      "Resource": "*"
    }
  ]
}
```

> Auditors can see configuration, policies, and logs. They cannot 
> read actual ePHI content. This is the minimum necessary standard 
> applied to the audit function.

---

### Role 3 — HealthcareAppRole

**Who uses it:** Application services — Lambda functions, ECS tasks, 
EC2 instances running healthcare applications that need to read and 
write ePHI.
**HIPAA principle:** Application service roles should be scoped to 
exactly the resources the application touches. No wildcards.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEPhIBucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-ephi-bucket-name",
        "arn:aws:s3:::your-ephi-bucket-name/*"
      ]
    },
    {
      "Sid": "AllowKMSForEncryption",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:<region>:<account-id>:key/<your-kms-key-id>"
    },
    {
      "Sid": "AllowLogging",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:<region>:<account-id>:log-group:/hipaa/*"
    },
    {
      "Sid": "DenyAllOther",
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*",
        "account:*",
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudwatch:DeleteAlarms"
      ],
      "Resource": "*"
    }
  ]
}
```

> Replace `your-ephi-bucket-name` and KMS key ID with your actual 
> resource identifiers. Never use `Resource: "*"` for ePHI access.

---

### Role 4 — HealthcareDeveloper

**Who uses it:** Developers building healthcare applications who 
need to deploy code and access non-production environments.
**HIPAA principle:** Developers should never have direct access 
to production ePHI. Separate production and development environments 
with separate roles.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowDevEnvironmentAccess",
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "lambda:*",
        "s3:*",
        "dynamodb:*",
        "logs:*",
        "cloudwatch:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Environment": "development"
        }
      }
    },
    {
      "Sid": "DenyProductionAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Environment": "production"
        }
      }
    }
  ]
}
```

> This uses resource tags to enforce the production/development 
> boundary. Tag all production resources with 
> `Environment: production` and development resources with 
> `Environment: development`. Developers are blocked from 
> production automatically.

---

## Creating Roles with AWS CLI
```powershell
# Create trust policy (who can assume this role)
# Save as trust_policy.json first

# Example trust policy for EC2 instances assuming HealthcareAppRole
$trustPolicy = @"
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ec2.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
"@

$trustPolicy | Out-File -FilePath "trust_policy.json" -Encoding UTF8

# Create the role
aws iam create-role `
  --role-name HealthcareAppRole `
  --assume-role-policy-document file://trust_policy.json `
  --description "Application role for services accessing ePHI - HIPAA aligned"

# Attach your custom permission policy
aws iam put-role-policy `
  --role-name HealthcareAppRole `
  --policy-name healthcare-app-permissions `
  --policy-document file://iam/policies/healthcare_app_role.json
```

---

## Compliance Evidence to Collect

- [ ] Screenshot of each role in IAM console showing policies attached
- [ ] Confirmation that no IAM users have direct S3 access to ePHI 
      buckets — all access goes through roles
- [ ] Screenshot showing production resources tagged with 
      `Environment: production`
- [ ] Access review log — who has permission to assume each role 
      and when that was last reviewed
- [ ] Confirmation that HealthcareAdmin role requires MFA — test 
      this by attempting to assume the role without MFA and 
      confirming it is denied
