# CloudWatch Alerts for Suspicious ePHI Activity

CloudTrail captures the logs — but logs sitting in S3 don't protect anyone. CloudWatch Metric Filters turn raw API event data into real-time alarms that fire when something suspicious happens to ePHI resources.

This file covers the five alerts every HIPAA-covered environment should have running.

---

## Why CloudWatch Alerts Are a HIPAA Control

HIPAA's Security Rule (§164.312(b)) requires covered entities to implement **audit controls** — mechanisms that record and examine activity in systems that contain ePHI. Logging alone satisfies the "record" half. Alerting satisfies the "examine" half.

Without active monitoring, you may have a 6-year log archive and still fail a HIPAA audit because no one is reviewing it.

---

## Prerequisites

- CloudTrail must be enabled in all regions with a trail writing to a CloudWatch Logs log group (see `01-cloudtrail-setup.md`)
- An SNS topic for alert delivery (email, PagerDuty, Slack via webhook)
- IAM permissions: `cloudwatch:PutMetricAlarm`, `logs:PutMetricFilter`, `sns:Publish`

---

## SNS Topic Setup

Create a single SNS topic to receive all security alerts:

```bash
aws sns create-topic --name hipaa-security-alerts

aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:hipaa-security-alerts \
  --protocol email \
  --notification-endpoint security@yourorganization.com
```

Save the topic ARN — you'll reference it in each alarm below.

---

## Alert 1 — Unauthorized API Calls

Fires when any API call returns an `AccessDenied` or `UnauthorizedOperation` response. A spike here often indicates credential misuse or a misconfigured role attempting lateral movement.

**Metric Filter:**

```bash
aws logs put-metric-filter \
  --log-group-name "CloudTrail/DefaultLogGroup" \
  --filter-name "UnauthorizedAPICalls" \
  --filter-pattern '{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") }' \
  --metric-transformations \
    metricName=UnauthorizedAPICalls,metricNamespace=HIPAA/CloudTrail,metricValue=1
```

**Alarm:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "HIPAA-UnauthorizedAPICalls" \
  --alarm-description "Unauthorized API calls detected — possible credential misuse" \
  --metric-name UnauthorizedAPICalls \
  --namespace HIPAA/CloudTrail \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:hipaa-security-alerts
```

---

## Alert 2 — Root Account Usage

Root account activity should be near zero in a production environment. Any root login or root API call is an immediate investigation trigger regardless of context.

**Metric Filter:**

```bash
aws logs put-metric-filter \
  --log-group-name "CloudTrail/DefaultLogGroup" \
  --filter-name "RootAccountUsage" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName=RootAccountUsage,metricNamespace=HIPAA/CloudTrail,metricValue=1
```

**Alarm:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "HIPAA-RootAccountUsage" \
  --alarm-description "Root account activity detected — immediate review required" \
  --metric-name RootAccountUsage \
  --namespace HIPAA/CloudTrail \
  --statistic Sum \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:hipaa-security-alerts
```

> **Note:** Threshold is set to 1 — a single root login is enough to fire this alarm.

---

## Alert 3 — IAM Policy Changes

Changes to IAM policies, roles, or users can expand access to ePHI resources. Alert on any create, attach, detach, or delete action targeting IAM objects.

**Metric Filter:**

```bash
aws logs put-metric-filter \
  --log-group-name "CloudTrail/DefaultLogGroup" \
  --filter-name "IAMPolicyChanges" \
  --filter-pattern '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)}' \
  --metric-transformations \
    metricName=IAMPolicyChanges,metricNamespace=HIPAA/CloudTrail,metricValue=1
```

**Alarm:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "HIPAA-IAMPolicyChanges" \
  --alarm-description "IAM policy change detected — verify this was authorized" \
  --metric-name IAMPolicyChanges \
  --namespace HIPAA/CloudTrail \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:hipaa-security-alerts
```

---

## Alert 4 — S3 Bucket Policy Changes

S3 bucket policy modifications on ePHI buckets can inadvertently (or intentionally) open data to public access. This alert catches any policy, ACL, or replication configuration change on S3.

**Metric Filter:**

```bash
aws logs put-metric-filter \
  --log-group-name "CloudTrail/DefaultLogGroup" \
  --filter-name "S3BucketPolicyChanges" \
  --filter-pattern '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }' \
  --metric-transformations \
    metricName=S3BucketPolicyChanges,metricNamespace=HIPAA/CloudTrail,metricValue=1
```

**Alarm:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "HIPAA-S3BucketPolicyChanges" \
  --alarm-description "S3 bucket policy change detected — verify ePHI bucket access controls" \
  --metric-name S3BucketPolicyChanges \
  --namespace HIPAA/CloudTrail \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:hipaa-security-alerts
```

---

## Alert 5 — CloudTrail Logging Disabled

If an attacker gains sufficient privileges, disabling CloudTrail is often one of the first things they do to cover their tracks. Alert immediately on any attempt to stop or delete a trail.

**Metric Filter:**

```bash
aws logs put-metric-filter \
  --log-group-name "CloudTrail/DefaultLogGroup" \
  --filter-name "CloudTrailChanges" \
  --filter-pattern '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }' \
  --metric-transformations \
    metricName=CloudTrailChanges,metricNamespace=HIPAA/CloudTrail,metricValue=1
```

**Alarm:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "HIPAA-CloudTrailChanges" \
  --alarm-description "CloudTrail configuration changed — logging integrity may be compromised" \
  --metric-name CloudTrailChanges \
  --namespace HIPAA/CloudTrail \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:hipaa-security-alerts
```

---

## Verifying Your Alerts

After deploying, confirm everything is wired correctly:

```bash
# List all metric filters on your CloudTrail log group
aws logs describe-metric-filters \
  --log-group-name "CloudTrail/DefaultLogGroup"

# List all alarms in the HIPAA namespace
aws cloudwatch describe-alarms \
  --alarm-name-prefix "HIPAA-"

# Confirm SNS subscriptions are confirmed (not PendingConfirmation)
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:hipaa-security-alerts
```

---

## Common Alerting Failures in Healthcare Environments

| Failure | Why It Matters |
|---|---|
| Alarms exist but SNS topic has no confirmed subscribers | Alert fires but no one receives it |
| Metric filter references wrong log group name | Filter never matches any events |
| Only alerting on CloudTrail — not reviewing alerts | Satisfies logging but not HIPAA's audit control requirement |
| No alarm on CloudTrail being disabled | Attacker disables logging; you have no record of what happened next |
| Root account alarm threshold set too high | Single root login goes undetected |

---

## HIPAA Mapping

| Alert | HIPAA Control |
|---|---|
| Unauthorized API Calls | §164.312(b) — Audit Controls |
| Root Account Usage | §164.312(a)(2)(i) — Unique User Identification |
| IAM Policy Changes | §164.312(a)(1) — Access Control |
| S3 Bucket Policy Changes | §164.312(a)(1) — Access Control; §164.312(e)(2)(ii) — Encryption |
| CloudTrail Disabled | §164.312(b) — Audit Controls |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
