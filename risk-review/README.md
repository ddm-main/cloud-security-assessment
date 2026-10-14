# Question 2: Risk review

| Document | Subject |
|---|---|
| [01-ssm-automation-policy.md](01-ssm-automation-policy.md) | Annexure A/B: SSM automation policy driven from Azure DevOps |
| [ssm-dispatcher-role-policy.json](ssm-dispatcher-role-policy.json), [ssm-execution-role-policy.json](ssm-execution-role-policy.json) | Replacement policies for the two roles in Annexure B |
| [rds-recommended-readonly-permission-set.json](rds-recommended-readonly-permission-set.json) | Starting point for the read-only database permission set |
| [02-rds-policies.md](02-rds-policies.md) | Annexure C/D: RDS ReadOnly / CRUD / Admin roles with SailPoint-Entra-Identity Center |

Both reviews use the same structure: verdict, risk register, and for each finding **risk -> mitigating controls -> possible outcome**, then what is good, an outcomes table, and conditions for approval.

## Headlines

**SSM:** *not approvable as is.* The tag gate on `SendCommand` is bypassable because the same role can write the tags (`ec2:CreateTags`), generic run-script documents give root-level code execution, S3 access spans every bucket, an unrelated account's `customer-*` documents are trusted, and the policy has syntax/account-ID defects.

**RDS:** *not approvable as is.* The "CRUB" (read/write) role has the same `rds:*` as Admin, none of the policies contain `rds-db:connect`, `rds:*` lets anyone reset the master password and bypass all DB-level roles, and leaver revocation and per-user attribution are unaddressed.
