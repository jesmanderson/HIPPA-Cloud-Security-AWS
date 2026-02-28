# CloudTrail Configuration for HIPAA Audit Controls

## HIPAA Requirement

The HIPAA Audit Controls standard (§164.312(b)) requires mechanisms 
to record and examine activity in systems containing ePHI. CloudTrail 
is the AWS service that satisfies this requirement; it records every 
API call made in your account, who made it, when, from where, and 
what the result was.

This is not optional for HIPAA-covered AWS environments. If you 
experience a breach and cannot produce CloudTrail logs showing 
what happened, you have both a security problem and a compliance 
problem.

---

## What CloudTrail Must Capture for HIPAA

| Log Type | What It Records | HIPAA Relevance |
|----------|----------------|-----------------|
| Management events | API calls that manage AWS resources — creating users, modifying policies, changing configurations | Required — covers all administrative actions |
| S3 data events | Object-level activity — who read, wrote, or deleted objects in S3 buckets containing ePHI | Required for any S3 bucket holding ePHI |
| CloudTrail log file validation | Detects if log files were modified or deleted after delivery | Required — ensures logs are tamper-evident |
| Multi-region trail | Captures activity in every AWS region, not just your primary region | Required — attackers target inactive regions |

---

## Step 1 — Create a Multi-Region Trail

A single-region trail only captures activity in one region. 
A multi-region trail captures everything. Always use multi-region 
for HIPAA environments.
```powershell
# Create S3 bucket to store CloudTrail logs
aws s3api create-bucket `
  --bucket your-hipaa-cloudtrail-logs `
  --region us-east-1

# Apply bucket policy to allow CloudTrail to write logs
# Save as cloudtrail_bucket_policy.json first (see Step 2)
aws s3api put-bucket-policy `
  --bucket your-hipaa-cloudtrail-logs `
  --policy file://cloudtrail_bucket_policy.json

# Create the multi-region trail
aws cloudtrail create-trail `
  --name hipaa-audit-trail `
  --s3-bucket-name your-hipaa-cloudtrail-logs `
  --is-multi-region-trail `
  --enable-log-file-validation `
  --include-global-service-events

# Start logging
aws cloudtrail start-logging `
  --name hipaa-audit-trail
```

---

## Step 2 — Protect the Log Bucket

CloudTrail logs are only useful as audit evidence if they cannot 
be tampered with. Apply this bucket policy to prevent log deletion 
and modification — including by administrators.

Save as `cloudtrail_bucket_policy.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::your-hipaa-cloudtrail-logs/AWSLogs/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    },
    {
      "Sid": "AllowCloudTrailBucketCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::your-hipaa-cloudtrail-logs"
    },
    {
      "Sid": "DenyLogDeletion",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Resource": "arn:aws:s3:::your-hipaa-cloudtrail-logs/*"
    },
    {
      "Sid": "DenyLogModification",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutBucketPolicy",
      "Resource": "arn:aws:s3:::your-hipaa-cloudtrail-logs",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::<account-id>:root"
        }
      }
    }
  ]
}
```

Enable versioning on the log bucket so deleted logs can be recovered:
```powershell
aws s3api put-bucket-versioning `
  --bucket your-hipaa-cloudtrail-logs `
  --versioning-configuration Status=Enabled
```

---

## Step 3 — Enable S3 Data Events for ePHI Buckets

Management events alone do not capture who read or wrote objects 
inside your S3 buckets. For any bucket containing ePHI, you must 
enable data event logging — otherwise you have no record of who 
accessed patient data.
```powershell
aws cloudtrail put-event-selectors `
  --trail-name hipaa-audit-trail `
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {
          "Type": "AWS::S3::Object",
          "Values": [
            "arn:aws:s3:::your-ephi-bucket-name/"
          ]
        }
      ]
    }
  ]'
```

> Replace `your-ephi-bucket-name` with every S3 bucket in your 
> account that contains ePHI. If you are not sure which buckets 
> contain ePHI, log all buckets until you complete a data 
> classification exercise.

---

## Step 4 — Enable Log File Validation

Log file validation creates a digest file for every log delivery 
that can be used to detect if logs were modified or deleted after 
CloudTrail delivered them. This is your tamper-evidence mechanism.
```powershell
aws cloudtrail update-trail `
  --name hipaa-audit-trail `
  --enable-log-file-validation
```

Verify log file integrity on demand:
```powershell
aws cloudtrail validate-logs `
  --trail-arn arn:aws:cloudtrail:<region>:<account-id>:trail/hipaa-audit-trail `
  --start-time 2026-01-01T00:00:00Z
```

---

## Step 5 — Verify Your Trail is Active

Run this audit script to confirm CloudTrail is configured correctly. 
Save as `scripts/audit_cloudtrail.ps1`:
```powershell
# CloudTrail HIPAA Compliance Audit
# Verifies trail configuration meets HIPAA audit control requirements
# HIPAA Standard: Audit Controls §164.312(b)

Write-Host "`n=== HIPAA CloudTrail Audit ===" -ForegroundColor Cyan
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm')`n"

$trails = aws cloudtrail describe-trails | ConvertFrom-Json

if ($trails.trailList.Count -eq 0) {
    Write-Host "❌ CRITICAL: No CloudTrail trails found." -ForegroundColor Red
    Write-Host "   This is a critical HIPAA gap — no audit trail exists." `
        -ForegroundColor Red
    exit
}

foreach ($trail in $trails.trailList) {
    Write-Host "Trail: $($trail.Name)" -ForegroundColor White
    
    # Check multi-region
    if ($trail.IsMultiRegionTrail) {
        Write-Host "  ✅ Multi-region trail enabled" -ForegroundColor Green
    } else {
        Write-Host "  ❌ FINDING: Single-region trail only — activity in other regions is not logged" `
            -ForegroundColor Red
    }
    
    # Check log file validation
    if ($trail.LogFileValidationEnabled) {
        Write-Host "  ✅ Log file validation enabled — logs are tamper-evident" `
            -ForegroundColor Green
    } else {
        Write-Host "  ❌ FINDING: Log file validation disabled — logs can be altered without detection" `
            -ForegroundColor Red
    }
    
    # Check logging status
    $status = aws cloudtrail get-trail-status `
        --name $trail.TrailARN | ConvertFrom-Json
    if ($status.IsLogging) {
        Write-Host "  ✅ Trail is actively logging" -ForegroundColor Green
    } else {
        Write-Host "  ❌ CRITICAL: Trail exists but logging is STOPPED" -ForegroundColor Red
    }

    # Check S3 bucket
    Write-Host "  📦 Logs delivered to: $($trail.S3BucketName)" -ForegroundColor Cyan

    Write-Host ""
}

Write-Host "Audit complete. Remediate any findings before next compliance review." `
    -ForegroundColor Cyan
Write-Host "Save this output as evidence under HIPAA §164.312(b)`n" `
    -ForegroundColor Yellow
```

---

## Step 6 — Set Log Retention to 6 Years

HIPAA requires that documentation, including audit logs, be 
retained for 6 years from creation or last effective date. 
Configure S3 lifecycle rules to enforce this.
```powershell
# Apply 6-year retention policy to log bucket
aws s3api put-bucket-lifecycle-configuration `
  --bucket your-hipaa-cloudtrail-logs `
  --lifecycle-configuration '{
    "Rules": [
      {
        "ID": "hipaa-6-year-retention",
        "Status": "Enabled",
        "Filter": { "Prefix": "" },
        "Transitions": [
          {
            "Days": 90,
            "StorageClass": "STANDARD_IA"
          },
          {
            "Days": 365,
            "StorageClass": "GLACIER"
          }
        ],
        "Expiration": {
          "Days": 2190
        }
      }
    ]
  }'
```

> 2190 days = 6 years. Logs transition to cheaper storage 
> as they age but are never deleted before the 6-year mark.

---

## Compliance Evidence to Collect

- [ ] Screenshot of CloudTrail console showing `hipaa-audit-trail` 
      active and multi-region enabled
- [ ] Screenshot showing log file validation is enabled
- [ ] Screenshot of S3 data events enabled for all ePHI buckets
- [ ] Output from `audit_cloudtrail.ps1` — all checks passing
- [ ] Screenshot of log bucket policy showing deletion is denied
- [ ] Screenshot of S3 lifecycle rule showing 6-year retention
- [ ] Document your log review process — who reviews logs, 
      how often, and what they look for. HIPAA requires the 
      mechanism AND the review process.
