# RDS & Backup Encryption at Rest

Encryption at rest for ePHI doesn't stop at S3. Database instances and backup vaults are equally high-value targets — and both have a critical constraint: **encryption must be enabled at creation time**. You cannot enable encryption on an existing unencrypted RDS instance or backup vault without rebuilding it.

---

## RDS Encryption at Rest

### Why RDS Encryption Requires Planning

RDS encryption is tied to the underlying EBS volume. AWS does not support enabling encryption on an existing unencrypted instance in place. The migration path for unencrypted RDS instances is:

1. Take a snapshot of the unencrypted instance
2. Copy the snapshot with encryption enabled
3. Restore the encrypted snapshot to a new instance
4. Update application connection strings
5. Delete the unencrypted instance

Auditing your environment for unencrypted RDS instances before a HIPAA assessment is critical.

---

### Creating an Encrypted RDS Instance

```bash
# Create a new RDS MySQL instance with encryption enabled from the start
aws rds create-db-instance \
  --db-instance-identifier hipaa-prod-db \
  --db-instance-class db.t3.medium \
  --engine mysql \
  --engine-version 8.0 \
  --master-username admin \
  --master-user-password YOUR_SECURE_PASSWORD \
  --allocated-storage 100 \
  --storage-type gp3 \
  --storage-encrypted \
  --kms-key-id arn:aws:kms:us-east-1:YOUR_ACCOUNT_ID:alias/hipaa-rds-ephi \
  --vpc-security-group-ids sg-YOUR_SG_ID \
  --db-subnet-group-name your-hipaa-subnet-group \
  --no-publicly-accessible \
  --deletion-protection \
  --backup-retention-period 35 \
  --preferred-backup-window "02:00-03:00" \
  --tags Key=HIPAAScope,Value=true Key=DataClassification,Value=ePHI
```

**Key parameters explained:**

- `--storage-encrypted` — enables AES-256 encryption on the EBS volume backing RDS
- `--kms-key-id` — pins encryption to your ePHI CMK (see `01-kms-setup.md`)
- `--no-publicly-accessible` — instance not reachable from the internet
- `--deletion-protection` — prevents accidental deletion
- `--backup-retention-period 35` — retains automated backups for 35 days (maximum); for HIPAA 6-year retention, use AWS Backup in addition

---

### Encrypting an Existing Unencrypted RDS Instance

```bash
# Step 1: Create a snapshot of the unencrypted instance
aws rds create-db-snapshot \
  --db-instance-identifier your-existing-unencrypted-db \
  --db-snapshot-identifier pre-migration-snapshot-$(date +%Y%m%d)

# Step 2: Copy the snapshot with encryption enabled
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier pre-migration-snapshot-$(date +%Y%m%d) \
  --target-db-snapshot-identifier encrypted-snapshot-$(date +%Y%m%d) \
  --kms-key-id arn:aws:kms:us-east-1:YOUR_ACCOUNT_ID:alias/hipaa-rds-ephi

# Step 3: Restore the encrypted snapshot to a new instance
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier hipaa-prod-db-encrypted \
  --db-snapshot-identifier encrypted-snapshot-$(date +%Y%m%d) \
  --db-instance-class db.t3.medium \
  --no-publicly-accessible \
  --deletion-protection
```

---

### Enabling RDS Audit Logging

RDS encryption satisfies the "at rest" requirement, but HIPAA also requires audit controls on who accessed the database. Enable audit logging and export to CloudWatch (see `../logging/02-cloudwatch-alerts.md` for retention):

```bash
# Enable audit, error, general, and slow query logs
aws rds modify-db-instance \
  --db-instance-identifier hipaa-prod-db \
  --cloudwatch-logs-export-configuration '{"EnableLogTypes":["audit","error","general","slowquery"]}' \
  --apply-immediately

# For Aurora MySQL — enable advanced auditing via parameter group
aws rds modify-db-cluster-parameter-group \
  --db-cluster-parameter-group-name hipaa-aurora-params \
  --parameters \
    ParameterName=server_audit_logging,ParameterValue=1,ApplyMethod=immediate \
    ParameterName=server_audit_events,ParameterValue="CONNECT,QUERY,TABLE",ApplyMethod=immediate
```

---

### Auditing RDS Encryption Status

```bash
# Find all unencrypted RDS instances in the account
aws rds describe-db-instances \
  --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier,DBInstanceClass,Engine]' \
  --output table

# Verify the KMS key in use for each encrypted instance
aws rds describe-db-instances \
  --query 'DBInstances[?StorageEncrypted==`true`].[DBInstanceIdentifier,KmsKeyId]' \
  --output table

# Check deletion protection status
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,DeletionProtection]' \
  --output table
```

---

## AWS Backup Encryption

### Why Backup Encryption Is a Separate Control

Encrypting the source database protects data at rest in RDS. But when AWS Backup creates a recovery point from that database, the backup is stored in a Backup Vault — and that vault has its own encryption configuration. If the vault is not encrypted with your CMK, backups of ePHI are protected by an AWS Managed Key that you cannot audit or control.

Additionally, AWS Backup is the correct tool for meeting HIPAA's 6-year retention requirement on database backups — RDS automated backups max out at 35 days.

---

### Creating an Encrypted Backup Vault

```bash
# Create a backup vault encrypted with your ePHI CMK
aws backup create-backup-vault \
  --backup-vault-name hipaa-ephi-backup-vault \
  --encryption-key-arn arn:aws:kms:us-east-1:YOUR_ACCOUNT_ID:alias/hipaa-backup-ephi \
  --backup-vault-tags HIPAAScope=true,DataClassification=ePHI

# Enable Vault Lock to prevent backup deletion (WORM protection)
# WARNING: Once locked in compliance mode, this cannot be undone
aws backup put-backup-vault-lock-configuration \
  --backup-vault-name hipaa-ephi-backup-vault \
  --min-retention-days 2557 \
  --changeable-for-days 3
```

> **Vault Lock:** Similar to S3 Object Lock. Once the `changeable-for-days` window passes, the lock is permanent and no user — including root — can delete recovery points before the minimum retention period expires. Set a test vault first and validate before applying to production.

---

### Creating a Backup Plan for ePHI Resources

```bash
# Create a backup plan with daily and monthly schedules
aws backup create-backup-plan \
  --backup-plan '{
    "BackupPlanName": "hipaa-ephi-backup-plan",
    "Rules": [
      {
        "RuleName": "DailyBackups",
        "TargetBackupVaultName": "hipaa-ephi-backup-vault",
        "ScheduleExpression": "cron(0 2 * * ? *)",
        "StartWindowMinutes": 60,
        "CompletionWindowMinutes": 180,
        "Lifecycle": {
          "DeleteAfterDays": 35
        },
        "RecoveryPointTags": {
          "BackupType": "daily",
          "HIPAAScope": "true"
        }
      },
      {
        "RuleName": "MonthlyBackupsLongRetention",
        "TargetBackupVaultName": "hipaa-ephi-backup-vault",
        "ScheduleExpression": "cron(0 3 1 * ? *)",
        "StartWindowMinutes": 60,
        "CompletionWindowMinutes": 360,
        "Lifecycle": {
          "MoveToColdStorageAfterDays": 90,
          "DeleteAfterDays": 2557
        },
        "RecoveryPointTags": {
          "BackupType": "monthly-longretention",
          "HIPAAScope": "true"
        }
      }
    ]
  }'
```

**Assign ePHI resources to the backup plan:**

```bash
# Get the backup plan ID from the create output, then assign resources
aws backup create-backup-selection \
  --backup-plan-id YOUR_BACKUP_PLAN_ID \
  --backup-selection '{
    "SelectionName": "hipaa-ephi-resources",
    "IamRoleArn": "arn:aws:iam::YOUR_ACCOUNT_ID:role/AWSBackupDefaultServiceRole",
    "ListOfTags": [
      {
        "ConditionType": "STRINGEQUALS",
        "ConditionKey": "HIPAAScope",
        "ConditionValue": "true"
      }
    ]
  }'
```

> **Tag-based selection:** Assigning resources by the `HIPAAScope=true` tag means any new RDS instance, EFS volume, or EBS volume tagged correctly is automatically included in the backup plan — no manual updates required.

---

### Verifying Backup Posture

```bash
# Confirm vault is encrypted with your CMK (not an AWS Managed Key)
aws backup describe-backup-vault \
  --backup-vault-name hipaa-ephi-backup-vault \
  --query '[BackupVaultName, EncryptionKeyArn]'

# List recent recovery points and confirm encryption
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name hipaa-ephi-backup-vault \
  --query 'RecoveryPoints[*].[RecoveryPointArn,CreationDate,IsEncrypted,EncryptionKeyArn]' \
  --output table

# Confirm Vault Lock configuration
aws backup get-backup-vault-lock-configuration \
  --backup-vault-name hipaa-ephi-backup-vault

# Check for any RDS instances not covered by a backup plan
aws backup list-protected-resources \
  --query 'Results[?ResourceType==`RDS`].[ResourceArn,LastBackupTime]' \
  --output table
```

---

## Common RDS & Backup Encryption Failures in Healthcare Environments

| Failure | Why It Matters |
|---|---|
| RDS instance created without `--storage-encrypted` | Cannot be encrypted in-place; requires rebuild |
| Backup vault using AWS Managed Key | Backups of ePHI not under your key policy control |
| Vault Lock not enabled | Recovery points can be deleted before 6-year retention window expires |
| Relying solely on RDS automated backups for retention | 35-day maximum does not satisfy HIPAA's 6-year documentation requirement |
| Backup plan not using tag-based selection | New ePHI resources added to the account silently fall outside backup coverage |
| RDS audit logging not enabled | Database access to ePHI not captured; gap in HIPAA audit trail |
| Deletion protection disabled | Accidental or malicious RDS deletion destroys the live ePHI store |

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| RDS storage encryption with CMK | §164.312(a)(2)(iv) — Encryption and Decryption |
| Backup vault encryption with CMK | §164.312(a)(2)(iv) — Encryption and Decryption |
| 6-year backup retention via AWS Backup | §164.530(j) — Documentation Retention |
| Vault Lock (WORM backup protection) | §164.312(c)(1) — Integrity Controls |
| RDS audit logging | §164.312(b) — Audit Controls |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
