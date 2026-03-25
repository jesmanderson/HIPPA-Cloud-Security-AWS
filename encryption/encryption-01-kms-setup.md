# KMS Key Setup & Key Policies for ePHI Encryption

AWS Key Management Service (KMS) is the foundation of encryption in a HIPAA-compliant AWS environment. Every service that encrypts ePHI at rest — S3, RDS, EBS, Backup — should use a Customer Managed Key (CMK) rather than an AWS Managed Key. CMKs give you control over key policy, rotation, auditing, and the ability to revoke access.

---

## AWS Managed Keys vs. Customer Managed Keys

| | AWS Managed Key | Customer Managed Key (CMK) |
|---|---|---|
| Who controls the key policy | AWS | You |
| Key rotation | Automatic (every 3 years) | Configurable (annual recommended) |
| Audit via CloudTrail | Limited | Full — every use logged |
| Cross-account access | No | Yes, with key policy |
| Cost | Free | $1/month per key + API call fees |
| HIPAA recommendation | Insufficient | Required |

For ePHI workloads, AWS Managed Keys are insufficient because you cannot restrict which IAM principals can use them, and you cannot audit key usage at the granularity HIPAA's audit controls require.

---

## Creating a CMK for ePHI Workloads

```bash
# Create a symmetric CMK for ePHI encryption
aws kms create-key \
  --description "HIPAA ePHI encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --tags TagKey=Environment,TagValue=production \
         TagKey=DataClassification,TagValue=ePHI \
         TagKey=HIPAAScope,TagValue=true

# Save the KeyId from the output, then create a human-readable alias
aws kms create-alias \
  --alias-name alias/hipaa-ephi-key \
  --target-key-id YOUR_KEY_ID
```

---

## Key Policy

The key policy is the primary access control mechanism for a CMK. IAM policies alone are not sufficient — the key policy must explicitly grant access.

A HIPAA-appropriate key policy follows least privilege: the key administrator can manage the key but cannot use it for encryption, and the key user can encrypt/decrypt but cannot modify the key.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootAccountAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyAdministration",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::YOUR_ACCOUNT_ID:role/KMSAdminRole"
        ]
      },
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyUseForEPHI",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::YOUR_ACCOUNT_ID:role/AppRole",
          "arn:aws:iam::YOUR_ACCOUNT_ID:role/RDSRole",
          "arn:aws:iam::YOUR_ACCOUNT_ID:role/BackupRole"
        ]
      },
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowAWSServicesViaGrantsOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:role/AppRole"
      },
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "kms:GrantIsForAWSResource": "true"
        }
      }
    },
    {
      "Sid": "DenyKeyDeletionWithoutMFA",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

Apply the policy:

```bash
aws kms put-key-policy \
  --key-id alias/hipaa-ephi-key \
  --policy-name default \
  --policy file://kms-key-policy.json
```

---

## Enable Annual Key Rotation

HIPAA does not specify a rotation interval, but annual rotation is the industry standard and satisfies most auditors and cyber insurance requirements.

```bash
aws kms enable-key-rotation \
  --key-id alias/hipaa-ephi-key

# Verify rotation is enabled
aws kms get-key-rotation-status \
  --key-id alias/hipaa-ephi-key
```

> **Note:** Enabling rotation does not re-encrypt existing data. AWS automatically uses the correct key version for decryption based on which version encrypted the data.

---

## Separate Keys by Workload

Using a single CMK for all ePHI resources creates blast radius risk — a misconfigured key policy or compromised role affects everything. The recommended approach is one key per major service or data boundary:

```bash
# Create separate keys for each major ePHI data store
for KEY_NAME in "hipaa-s3-ephi" "hipaa-rds-ephi" "hipaa-backup-ephi" "hipaa-ebs-ephi"; do
  aws kms create-key \
    --description "HIPAA $KEY_NAME encryption key" \
    --key-usage ENCRYPT_DECRYPT \
    --key-spec SYMMETRIC_DEFAULT \
    --tags TagKey=HIPAAScope,TagValue=true
  
  aws kms create-alias \
    --alias-name "alias/$KEY_NAME" \
    --target-key-id $(aws kms list-keys --query 'Keys[-1].KeyId' --output text)
  
  echo "Created key: alias/$KEY_NAME"
done
```

---

## Auditing KMS Key Usage

Every KMS API call is logged in CloudTrail. Use this to verify keys are only being used by authorized principals:

```bash
# Review recent KMS Decrypt calls
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
  --max-results 50 \
  --query 'Events[*].[EventTime,Username,Resources[0].ResourceName]' \
  --output table

# Check for any key access by unexpected principals
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=alias/hipaa-ephi-key \
  --max-results 100
```

---

## Verifying Your KMS Posture

```bash
# List all CMKs and their descriptions
aws kms list-keys --query 'Keys[*].KeyId' --output text | \
  xargs -I {} aws kms describe-key --key-id {} \
  --query 'KeyMetadata.[KeyId,Description,KeyState,KeyRotationStatus]'

# Identify any keys that are scheduled for deletion
aws kms list-keys --query 'Keys[*].KeyId' --output text | \
  xargs -I {} aws kms describe-key --key-id {} \
  --query 'KeyMetadata[?KeyState==`PendingDeletion`]'

# Confirm rotation is enabled across all CMKs
aws kms list-keys --output text --query 'Keys[*].KeyId' | \
  tr '\t' '\n' | \
  xargs -I {} sh -c 'echo -n "Key {}: "; aws kms get-key-rotation-status --key-id {} --query RotationEnabled --output text'
```

---

## Common KMS Failures in Healthcare Environments

| Failure | Why It Matters |
|---|---|
| Using AWS Managed Keys instead of CMKs | Cannot restrict key usage; limited audit visibility |
| Single CMK for all ePHI resources | Misconfigured policy or compromised role exposes all data |
| Key rotation not enabled | Violates security best practice; flags in cyber insurance audits |
| Key policy grants `kms:*` to application roles | Application can delete or disable its own encryption key |
| No CloudTrail monitoring of KMS usage | Cannot detect unauthorized decryption of ePHI |
| Key deletion not MFA-protected | Accidental or malicious key deletion destroys access to all encrypted data |

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| Encryption of ePHI at rest using CMKs | §164.312(a)(2)(iv) — Encryption and Decryption |
| Key access restricted to authorized roles | §164.312(a)(1) — Access Control |
| Key usage audited via CloudTrail | §164.312(b) — Audit Controls |
| Annual key rotation | §164.306(a)(1) — Risk Analysis (reducing exposure window) |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
