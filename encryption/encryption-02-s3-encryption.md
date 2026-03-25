# S3 Encryption — SSE-KMS & Bucket Policies for ePHI

S3 is one of the most common ePHI data stores in cloud-native healthcare environments — and one of the most commonly misconfigured. Enabling encryption on an S3 bucket is not enough on its own. You also need to enforce encryption on every upload, block unencrypted access paths, and ensure the bucket cannot be made public.

---

## S3 Encryption Options Compared

| Method | Key Control | HIPAA Suitability | Notes |
|---|---|---|---|
| SSE-S3 (AES-256) | AWS manages everything | Marginal | No key policy control; limited audit |
| SSE-KMS | You control via CMK | Recommended | Full CloudTrail visibility; key policy enforced |
| SSE-C | Customer provides key per request | Niche | Complex key management; rarely used |
| Client-side encryption | You manage entirely | Acceptable | Adds application complexity |

For ePHI buckets, **SSE-KMS with a Customer Managed Key** is the standard. It gives you key policy control, per-request CloudTrail logging, and the ability to revoke access at the key level.

---

## Creating an ePHI S3 Bucket

```bash
# Create the bucket (us-east-1 does not require LocationConstraint)
aws s3api create-bucket \
  --bucket your-org-ephi-data \
  --region us-east-1

# Tag it for HIPAA scope tracking
aws s3api put-bucket-tagging \
  --bucket your-org-ephi-data \
  --tagging 'TagSet=[{Key=DataClassification,Value=ePHI},{Key=HIPAAScope,Value=true},{Key=Environment,Value=production}]'
```

---

## Step 1 — Block All Public Access

This must be set before anything else. No ePHI bucket should ever be publicly accessible.

```bash
aws s3api put-public-access-block \
  --bucket your-org-ephi-data \
  --public-access-block-configuration \
    BlockPublicAcls=true,\
    IgnorePublicAcls=true,\
    BlockPublicPolicy=true,\
    RestrictPublicBuckets=true

# Verify
aws s3api get-public-access-block \
  --bucket your-org-ephi-data
```

---

## Step 2 — Enable Default Encryption with SSE-KMS

Default encryption applies SSE-KMS to any object uploaded without an explicit encryption header. Combined with the bucket policy in Step 3, this creates a two-layer enforcement.

```bash
aws s3api put-bucket-encryption \
  --bucket your-org-ephi-data \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "aws:kms",
          "KMSMasterKeyID": "arn:aws:kms:us-east-1:YOUR_ACCOUNT_ID:alias/hipaa-s3-ephi"
        },
        "BucketKeyEnabled": true
      }
    ]
  }'
```

> **BucketKeyEnabled:** Setting this to `true` significantly reduces KMS API call costs by generating a short-lived bucket-level data key rather than calling KMS for every object. Strongly recommended for high-volume ePHI buckets.

---

## Step 3 — Enforce Encryption via Bucket Policy

Default encryption handles uploads from the console and SDK, but a bucket policy is the only way to **deny** uploads that attempt to use a different encryption method or no encryption at all.

```bash
aws s3api put-bucket-policy \
  --bucket your-org-ephi-data \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyUnencryptedUploads",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::your-org-ephi-data/*",
        "Condition": {
          "StringNotEquals": {
            "s3:x-amz-server-side-encryption": "aws:kms"
          }
        }
      },
      {
        "Sid": "DenyWrongKMSKey",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::your-org-ephi-data/*",
        "Condition": {
          "StringNotEquals": {
            "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:YOUR_ACCOUNT_ID:alias/hipaa-s3-ephi"
          }
        }
      },
      {
        "Sid": "DenyHTTPAccess",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::your-org-ephi-data",
          "arn:aws:s3:::your-org-ephi-data/*"
        ],
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        }
      },
      {
        "Sid": "DenyNonOrgAccess",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::your-org-ephi-data",
          "arn:aws:s3:::your-org-ephi-data/*"
        ],
        "Condition": {
          "StringNotEquals": {
            "aws:PrincipalOrgID": "YOUR_ORG_ID"
          }
        }
      }
    ]
  }'
```

**What each statement does:**

- `DenyUnencryptedUploads` — blocks any `PutObject` not using SSE-KMS
- `DenyWrongKMSKey` — ensures only your designated ePHI CMK is used, not another key or an AWS Managed Key
- `DenyHTTPAccess` — blocks all non-TLS requests to the bucket
- `DenyNonOrgAccess` — prevents access from principals outside your AWS Organization

---

## Step 4 — Enable Versioning and MFA Delete

Versioning protects against accidental overwrite. MFA Delete prevents permanent deletion without a second factor.

```bash
# Enable versioning
aws s3api put-bucket-versioning \
  --bucket your-org-ephi-data \
  --versioning-configuration Status=Enabled

# Enable MFA Delete (requires root credentials and a hardware MFA device)
aws s3api put-bucket-versioning \
  --bucket your-org-ephi-data \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::YOUR_ACCOUNT_ID:mfa/root-account-mfa-device YOUR_MFA_CODE"
```

---

## Step 5 — Enable S3 Access Logging

S3 server access logs capture object-level read and write activity. Required for HIPAA audit controls on ePHI bucket access.

```bash
# Create a dedicated logging bucket (separate from ePHI data)
aws s3api create-bucket \
  --bucket your-org-s3-access-logs \
  --region us-east-1

# Enable logging on the ePHI bucket, writing to the log bucket
aws s3api put-bucket-logging \
  --bucket your-org-ephi-data \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "your-org-s3-access-logs",
      "TargetPrefix": "ephi-data/"
    }
  }'
```

> Apply the same Object Lock and lifecycle tiering from `../logging/03-log-retention.md` to your S3 access log bucket.

---

## Verifying Encryption Posture

```bash
# Confirm default encryption is set
aws s3api get-bucket-encryption \
  --bucket your-org-ephi-data

# Confirm public access block is fully enabled
aws s3api get-public-access-block \
  --bucket your-org-ephi-data

# Check for any objects that are not encrypted with SSE-KMS
aws s3api list-objects-v2 \
  --bucket your-org-ephi-data \
  --query 'Contents[*].Key' --output text | \
  xargs -I {} aws s3api head-object \
    --bucket your-org-ephi-data \
    --key {} \
    --query '[ServerSideEncryption, SSEKMSKeyId]' \
    --output text

# Audit bucket policy is in place
aws s3api get-bucket-policy \
  --bucket your-org-ephi-data
```

---

## Common S3 Encryption Failures in Healthcare Environments

| Failure | Why It Matters |
|---|---|
| Default encryption set but no bucket policy | Encryption is a default, not a requirement — applications can still upload unencrypted objects |
| Using SSE-S3 instead of SSE-KMS | No key policy control; AWS Managed Key cannot be restricted or audited per-request |
| Not pinning to a specific CMK | AWS may use the default `aws/s3` managed key when no key is specified |
| Public access block disabled | Single misconfigured ACL or policy can expose ePHI publicly |
| No versioning or MFA Delete | Accidental or malicious deletion permanently destroys ePHI |
| S3 access logging not enabled | Object-level reads and writes to ePHI not captured for HIPAA audit |
| BucketKeyEnabled = false on high-volume buckets | Not a security failure, but excessive KMS costs often lead teams to disable KMS encryption |

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| SSE-KMS encryption of ePHI objects | §164.312(a)(2)(iv) — Encryption and Decryption |
| Bucket policy denying HTTP access | §164.312(e)(2)(ii) — Encryption in Transit |
| Access logging on ePHI buckets | §164.312(b) — Audit Controls |
| Block public access + MFA Delete | §164.312(c)(1) — Integrity Controls |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
