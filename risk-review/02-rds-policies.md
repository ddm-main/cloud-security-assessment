# Review 2: RDS role policies (Annexure C / D)

**Use case:** replace shared DB credentials with three user-specific access levels, granted through the chain
`SailPoint request -> Entra ID group -> IAM Identity Center (SAML/SCIM) -> Permission Set (rds-db:connect) -> RDS IAM auth token -> DB role`:

| Role | Intended DB access |
|---|---|
| ReadOnly | `SELECT` |
| "CRUB" (read/write, presumably CRUD) | `SELECT, INSERT, UPDATE, DELETE` |
| Admin | full DDL + DML |

## What the diagram shows (Annexure D)

- **Access Management:** SailPoint (Predefined Roles leading to Permissions) is joined by a dotted "Integrate" arrow to Azure Entra ID (User leading to Groups).
- **AWS Environment:** the Entra groups feed three IAM roles drawn in an "IAM" box, named **`admin`, `ReadOnly` and `CRUB`**. Each role leads to a database user or group of the same purpose inside one RDS instance: **Admin (DDL)**, **ReadOnly (Select)** and **CRUD (CRUD)**, all on one database.
- **The text under the diagram** describes a different path: Entra security group, then **AWS IAM Identity Center** (SAML), then a **permission set** scoped to `rds-db:connect`, then an IAM-authentication token into a database role.
- Not shown: how users reach the database (the VPC is drawn but there is no network path), TLS, auditing, any second environment, or which Region.

Two things follow, covered in R10: the picture and the text disagree about how people sign in, and the names are inconsistent.

## Verdict

**Do not approve the policies as written.** The architecture (central identity, no static passwords, token-based login) is sound, but **the policies submitted do not implement it**, and two of the three grant far more than their names say.

**Core gap:** the three policies are IAM **control-plane** policies (`rds:*`, `rds:Describe*`) that manage RDS *instances*. Logging in and running `SELECT`/`INSERT`/DDL needs the **data-plane** permission `rds-db:connect`, and *what a login can do* is decided by **grants inside the database**, not by IAM. No policy contains `rds-db:connect`.

## Risk register

| # | Finding | Severity |
|---|---|---|
| R1 | "CRUB" role has `rds:*` on `*`, identical to Admin's control plane | **Critical** |
| R2 | Admin = near copy of `AmazonRDSFullAccess`: `rds:*`, `logs:GetLogEvents` on `*`, `sns:Publish` on `*`, alarm deletion, `pi:*` | **High** |
| R3 | Policies contain no `rds-db:connect`; access tiers can't be enforced as designed | **High** (design) |
| R4 | `rds:*` allows bypassing every DB-level control (reset master password, snapshot share/restore) | **Critical** |
| R5 | Leaver/mover gap: SCIM lag, long sessions, live DB connections survive revocation | **High** |
| R6 | Shared DB user per tier = no individual accountability; token minting isn't logged | **High** |
| R7 | DB-side grants unmanaged/unreviewed (drift, default privileges, `PUBLIC`) | **Medium-High** |
| R8 | Missing network, TLS, logging, and engine details in the design | **Medium** |
| R9 | ReadOnly role: broad metadata disclosure; read access to sensitive data | **Medium** |
| R10 | The diagram and its text disagree on the sign-in path; role names are generic and inconsistent | **Medium** |

## Findings in detail

### R1: "CRUB" role is effectively an RDS administrator (Critical)
- **What:** `CRUB Role policy` is `rds:* on *`, the same RDS permissions as Admin. A read/write *data* role should need **zero** `rds:*` actions.
- **Abuse:** a user meant to `UPDATE` rows can `DeleteDBInstance`, `ModifyDBInstance` (make public, disable backups, reset password), or `DeleteDBSnapshot`.
- **Mitigations:** remove `rds:*` entirely from the CRUD tier; give it `rds-db:connect` for the CRUD DB user only plus read-only Describe if needed. Naming: fix "CRUB" -> "CRUD" before it becomes an identifier in SailPoint/Entra/IaC and is hard to rename.
- **Outcome:** privilege-escalation by design: any CRUD user can destroy the database or exfiltrate it.
- **Tested on a real database:** the "CRUB" role reset the master password, was allowed to attempt deletion and shared a snapshot with another account (see [aws-validation](../aws-validation/README.md)).

### R2: Admin policy is over-broad for the stated purpose (High)
It matches the AWS-managed `AmazonRDSFullAccess` policy almost line for line; the use case only needs **DB-level** DDL/DML for this role.
- `rds:*` on `*`: every RDS resource in the account, in every Region (the Q3 SCP narrows the Regions).
- `logs:GetLogEvents`/`DescribeLogStreams` on `*`: reads **every** CloudWatch log group (app logs, CloudTrail-to-CW, secrets in logs).
- `sns:Publish` / `ListSubscriptions` on `*`: spoof alerts, trigger subscribers, enumerate emails.
- `cloudwatch:DeleteAlarms` / `PutMetricAlarm` on `*`: blind monitoring.
- `application-autoscaling:*` write, `iam:CreateServiceLinkedRole` (limited to RDS, low risk).
- `devops-guru:SearchInsights` / `ListAnomaliesForInsight`: the `ForAllValues:StringEquals` + `Null:false` condition limits them to RDS, but only when the key is present. Test it with the policy simulator, or drop DevOps Guru if it is not used.
- `pi:*` on `rds/*`: Performance Insights exposes **SQL text, often with literal values/PII**.
- **Mitigations:** split into two personas: a *DBA* (DB-level admin via `rds-db:connect`, minimal control-plane read) and a *Platform/RDS operator* (control plane, scoped to named instances by tag/ARN, with MFA and change tickets). Resource-scope everything; add `aws:RequestedRegion`/`aws:ResourceTag` conditions; grant `pi:GetResourceMetrics` etc. read-only, only where needed.

### R3: Policies don't implement the design (High)
- With IAM DB authentication, IAM authorises *"may connect as DB user X"* via
  `arn:aws:rds-db:eu-west-1:<acct>:dbuser:<DbiResourceId>/<db-username>`. Each tier needs **its own DB user** (`app_readonly`, `app_crud`, `app_admin`) created `IDENTIFIED WITH AWSAuthenticationPlugin` (MySQL) or `GRANT rds_iam` (PostgreSQL), with `GRANT`s inside the DB. IAM cannot express "SELECT only"; the DB does.
- The ReadOnly policy (Describe* only) therefore **cannot connect at all**; users will ask for a quick fix, which tends to be `rds:*` or the master password.
- **Engine check:** IAM DB auth supports MySQL/MariaDB/PostgreSQL (and Aurora equivalents). It is **not** available for Oracle/SQL Server/Db2 (those need Kerberos/AD); confirm the engine.
- **Tested on a real database:** a role carrying any of the three Annexure C policies was refused when it tried to log in. A role with `rds-db:connect` for one user could log in only as that user, and what the user could then do (SELECT only, CRUD, or DDL) was decided entirely by the database grants (see [aws-validation](../aws-validation/README.md)).
- **Mitigations:** define the three DB users and grants as code (migrations/Terraform provider), and issue permission sets such as:

```json
{ "Version": "2012-10-17", "Statement": [
  { "Effect": "Allow", "Action": "rds-db:connect",
    "Resource": "arn:aws:rds-db:eu-west-1:<ACCOUNT_ID>:dbuser:<DbiResourceId>/app_readonly" },
  { "Effect": "Allow", "Action": ["rds:DescribeDBInstances", "rds:DescribeDBClusters"], "Resource": "*",
    "Condition": { "StringEquals": { "aws:RequestedRegion": "eu-west-1" } } } ] }
```
Enforce MFA in **Entra ID Conditional Access**, not with `aws:MultiFactorAuthPresent` in the permission set: federated (SAML) sessions normally do not carry that key, so such a condition would deny everyone. Tested: a role session started without MFA is denied by a policy that requires the key, and allowed by the same policy without the condition. This used an assumed-role session, which has the same missing key; SAML behaviour is AWS-documented but was not tested with a SAML assertion.

### R4: Control-plane rights bypass DB-level separation (Critical)
Anyone with `rds:ModifyDBInstance` can **set a new master password** -> DB superuser, defeating ReadOnly/CRUD/Admin grants. Related bypasses under `rds:*`: `RestoreDBInstanceFromDBSnapshot` (restore a copy, then reset its password), `ModifyDBSnapshotAttribute` (share a snapshot with an outside account), `CopyDBSnapshot`, `StartExportTask` (export to S3), `DownloadDBLogFilePortion`, `ModifyDBParameterGroup` (turn off auditing / `force_ssl`), `DeleteDBInstance` with `skip-final-snapshot`, make instance `PubliclyAccessible`.
- **Mitigations:** least-privilege control plane; **SCP/permission boundary** denying these actions except for a break-glass/IaC role; RDS **deletion protection** on; manage master credentials with `--manage-master-user-password` (Secrets Manager, rotated), restricting `secretsmanager:GetSecretValue`; snapshots encrypted with a CMK whose key policy excludes these roles; an SCP denying `rds:ModifyDBSnapshotAttribute` to external accounts; alert on `ModifyDBInstance`/`ModifyDBSnapshotAttribute`/`RestoreDBInstance*`.
- **Outcome:** the whole "user-specific roles" investment is nullified by one API call.
- **Tested on a real database:** both the CRUB and Admin roles could reset the master password and share a snapshot; ReadOnly could not.

### R5: Joiner/mover/leaver timing (High)
Revocation path: SailPoint removes access -> Entra group updated -> **SCIM sync to Identity Center (can lag)** -> assignment removed. But:
- Existing **Identity Center sessions** keep working until their duration expires (up to 12 h).
- A minted **IAM auth token is valid 15 min**, but an **established DB connection stays open indefinitely**.
- **Mitigations:** short permission-set session duration (1 h; admin <= 30 min); JIT/time-boxed admin via SailPoint with auto-expiry; on leaver, revoke the session (deny policy on `aws:TokenIssueTime`) **and** terminate DB sessions (`pg_terminate_backend`/`KILL`); server-side idle/lifetime limits; periodic access recertification in SailPoint. Test and document SCIM sync latency.
- **Outcome:** a leaver or role-changer retains DB access for hours.
- **Tested with real role sessions:** a deny on `aws:TokenIssueTime` cuts off a session issued before it at once, while a session started afterwards works. A live session is also cut off at once if its role's permissions are deleted, and its credentials are rejected outright if the role is deleted. Removing someone from an identity provider group changes nothing in IAM, so their existing credentials keep working until they expire unless the roles are revoked (see [aws-validation](../aws-validation/README.md)).

### R6: Accountability gap: shared DB users (High)
All members of ReadOnly connect as the **same** DB user, so DB audit logs show `app_readonly`, not a person. Token generation is a local SigV4 signature, so **no CloudTrail event** records who minted a token.
- **Mitigations:** DB audit logging (`pgaudit` / MariaDB audit plugin / MySQL audit) shipped to CloudWatch with a retained, access-controlled log group; correlate with the Identity Center sign-in events (CloudTrail `sso`/`signin`) and source IP/VPN logs; where feasible, **per-person DB users** for admin tier at minimum (policy scoped to that user), or access via a logged bastion/SSM port-forward (session logging); add GuardDuty RDS Protection for anomalous logins.
- **Outcome:** insider data theft or an accidental `DELETE` can't be attributed; weak for audits (SOX/PCI/GDPR).

### R7: DB-side grant management (Medium-High)
- Privileges live in the database: no IAM guardrail stops a DBA granting `ReadOnly` extra rights. Control drift with grants as code and scheduled diff/alert.
- PostgreSQL: revoke `CREATE` on `public` from `PUBLIC` (default in <15), set `ALTER DEFAULT PRIVILEGES` so new tables aren't silently unreadable (which creates pressure to over-grant) *or* silently over-exposed.
- Admin "Full DDL + DML" must **not** be `rds_superuser`/master unless truly required; remove the ability to create users/grants from the routine admin tier.
- Consider row/column-level security or masking for PII; ReadOnly can still read everything it is granted (R9).

### R8: Gaps in the design (Medium)
- **Network:** no path is shown. Require private subnets, no public accessibility, security groups limited to the access path (VPN/bastion/SSM port-forward/RDS Proxy), no `0.0.0.0/0`.
- **TLS:** IAM auth uses SSL; enforce `rds.force_ssl=1`/`require_secure_transport` and validate server certificates (RDS CA bundle).
- **Limits:** IAM DB auth has a connection-rate ceiling; use connection pooling/RDS Proxy for apps. Do not use per-person IAM auth for high-churn application traffic.
- **Scope:** one account/Region/VPC is drawn; multi-account needs per-account permission-set assignments and **separate prod/non-prod** groups.
- **Logging/monitoring:** CloudTrail (management events), DB audit logs, Enhanced Monitoring, alarms on parameter-group, snapshot, and master-password changes.

### R9: ReadOnly tier (Medium)
`rds:Describe*` reveals endpoints, master usernames, VPC/SG IDs, snapshot attributes (`DescribeDBSnapshotAttributes`), and log file names. Limit to `DescribeDBInstances`/`DescribeDBClusters` and tags. Separately, "SELECT only" can still read PII at scale; apply classification, per-schema grants, and a data-access review for production.

### R10: Diagram and text disagree; names are generic (Medium)
- **Sign-in path:** the diagram sends Entra groups straight to three IAM roles, which is how a plain IAM SAML provider works (each group mapped to a role). The text uses IAM Identity Center permission sets, which create their own roles (`AWSReservedSSO_...`) in each account and are assigned per account and group. The two need different controls: SAML provider trust and role-mapping claims in one case, permission set assignments, SCIM and session duration in the other. Decide which one is real before approving the policies, because Annexure C's three policies would be attached in different places.
- **Names:** the IAM roles are `admin`, `ReadOnly` and `CRUB`, the database users are `Admin`, `ReadOnly` and `CRUD`. "CRUB" is a typo, and a role called plain `admin` invites confusion with a database superuser or an AWS administrator. Use explicit, environment-qualified names (for example `rds-prod-readonly`) for both the roles and the database users, and fix the typo before it becomes an identifier in SailPoint and Entra.
- **Mitigation:** one documented sign-in path, consistent names, and the mapping role to database user written down (one database user per role, created by code).
- **Outcome:** the wrong control gets reviewed, and access reviews in SailPoint cannot be matched to what exists in AWS.

## What is good (keep)
- Centralised joiner/mover/leaver via SailPoint -> Entra groups; MFA at the IdP.
- No long-lived DB passwords for humans (IAM auth tokens last 15 minutes).
- Three clear access tiers and `iam:CreateServiceLinkedRole` correctly condition-limited to RDS.

## Possible outcomes summary

| Scenario | Today | After mitigation |
|---|---|---|
| CRUD user turns malicious | Deletes/modifies/exfiltrates the DB via `rds:*` (R1, R4) | Can only run granted DML |
| Leaver at 09:00 | Still connected for hours (R5) | Sessions revoked and DB sessions killed within minutes |
| Audit asks "who ran this DELETE?" | `app_crud`, unknown person (R6) | Audit log + sign-in correlation / per-user admin |
| Admin reads logs/alerts | Reads all log groups; spoofs SNS (R2) | Scoped to RDS log groups; no SNS publish |
| Snapshot shared externally | Possible (R4) | SCP-denied and alerted |

## Recommended approval conditions
1. Remove `rds:*` from CRUD; split Admin into DBA vs RDS operator (R1, R2). 2. Add `rds-db:connect` per DB user, with DB grants defined as code (R3, R7). A starting point is in [rds-recommended-readonly-permission-set.json](rds-recommended-readonly-permission-set.json). 3. Add SCP/boundary guardrails for destructive/bypass RDS actions (R4). 4. Define revocation SLAs and session limits (R5). 5. Enable audit logging and an attribution plan (R6). 6. Provide DB engine, network path, TLS and prod/non-prod separation (R8). 7. Settle one sign-in path and one naming scheme (R10). Re-review after resubmission.
