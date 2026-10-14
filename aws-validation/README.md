# AWS validation

The SCPs and policies in this repo were tested with real calls against real AWS (GitHub and Microsoft Entra ID for the OIDC parts). There is no simulated result here. Each script cleans up after itself and was last run with nothing left behind.

| Script | What it tests | Checks | Cost |
|---|---|---|---|
| `real_scp_test.py` | The three SCPs attached in a real Organization, probed from a member account | 15 | free |
| `real_scp_boundary_test.py` | The same rules against KMS, S3, Lambda, SNS, EC2, RDS, SSM, DynamoDB, Logs, CloudFront, Route 53, IAM, Organizations | 50 | free |
| `real_ssm_test.py` | The SSM policy as printed, corrected, and the hardened execution-role policy, on real instances | 33 | cents |
| `real_ssm_e2e_test.py` | The Annexure B flow with the split dispatcher and execution role policies | 12 | cents |
| `real_rds_test.py` | The Annexure C RDS policies against a real database | 28 | cents, ~20 min |
| `real_rds_login_test.py` | Logging in with IAM tokens, and what each database user can do | 25 | cents, ~20 min |
| `real_rds_restore_test.py` | Restore from snapshot, per role, without building a database | 4 | free |
| `real_session_test.py` | MFA conditions, session revocation, permissions removed, role deleted | 9 | free |
| `real_oidc_trust_test.py` | Pinning an OIDC token's subject and audience in a role trust policy (GitHub Actions as issuer) | 11 | free |
| `real_entra_oidc_test.py` | A real Microsoft Entra ID token in a role trust policy, v1 and v2 token formats | 10 | free |

197 checks. The scripts use the AWS CLI with `AWS_PROFILE`; the OIDC one also needs `gh`, and the login test needs `psql` (`brew install libpq`). They create real resources, so run them only in an account you can spare. `annexure-a-as-printed.json` is a rebuild of the PDF's policy (its text has empty statements and missing commas; the S3 bucket ARN keeps its stray space), `annexure-a-account-fixed.json` has only the account ID typo corrected, and `rds-*.json` are the Annexure C policies.

```bash
export AWS_PROFILE=<account to test in>          # for real_scp_test.py use the management account of an Organization
python3 aws-validation/real_scp_test.py
python3 aws-validation/real_scp_boundary_test.py
python3 aws-validation/real_ssm_test.py
python3 aws-validation/real_ssm_e2e_test.py
SHARE_WITH_ACCOUNT=<another account ID> python3 aws-validation/real_rds_test.py
python3 aws-validation/real_rds_login_test.py
python3 aws-validation/real_rds_restore_test.py
python3 aws-validation/real_session_test.py
python3 aws-validation/real_oidc_trust_test.py
python3 aws-validation/real_entra_oidc_test.py --token-version 1     # needs az login; also run with --token-version 2
```

## SCPs

| Policy on the OU | ECR eu-west-1 | ECR in other Regions | IAM (global) |
|---|---|---|---|
| none | allowed | allowed | allowed |
| main SCP | allowed | **denied** | allowed |
| strict SCP | allowed | **denied** | **denied** |
| break-glass variant, exempt role / other role | allowed / allowed | allowed / **denied** | not tested |

A new member account only has a few services active at first, so the same rules were also run as a permissions boundary on a role in an account with everything active. With the main SCP, KMS, S3, Lambda, SNS, EC2, RDS, Systems Manager, DynamoDB and Logs work in eu-west-1 and are denied in us-east-1; IAM, Route 53, CloudFront and Organizations keep working. The strict SCP denies those global services too, which is why the exception-list version is the one to deploy. A boundary and an SCP both honour explicit denies, but the boundary test does not prove the Organizations attachment; the first test does.

## SSM

| Call | PDF policy (typo fixed) | Execution-role policy |
|---|---|---|
| Tag an untagged instance with the gate tags, then run a command on it | **works** | tagging denied |
| `SendCommand` with `AWS-RunShellScript` | **works** | denied |
| `SendCommand` with a `customer-*` document from another account | **authorised** | denied |
| Read an S3 bucket unrelated to deployments | **works** | denied |
| Stop an instance, start an untagged instance (dry run) | **allowed** | denied |
| `SendCommand` with the approved document to the tagged instance | works | works |

- The approved command really ran on the instance.
- The policy exactly as printed (11-digit account ID) is accepted by IAM, although Access Analyzer calls it an error, and its EC2 statement matches nothing.
- **End to end (Annexure B):** the dispatcher role started the runbook and the command ran on the tagged instance. On an untagged instance the execution failed with an access-denied error. The dispatcher was denied passing any other role, starting another runbook, `SendCommand`, a session and tagging; an ordinary principal could not assume the execution role.
- AWS checks `StartAutomationExecution` against the runbook as `document/<name>` plus `automation-execution/*`, not an `automation-definition/...` ARN. My first policy used the wrong one and the real service rejected it.

## RDS

| Call made as the role | ReadOnly | Recommended set | "CRUB" | Admin |
|---|---|---|---|---|
| Reset the master password | denied | denied | **OK** | OK |
| Delete the instance (stopped only by deletion protection) | denied | denied | **allowed** | allowed |
| Share the snapshot with another account | denied | denied | **OK** | OK |
| Restore from a snapshot | denied | denied | **allowed** | allowed |
| Read an unrelated log group / publish to an unrelated topic / delete an alarm | denied | denied | denied | **OK** |

- **Login test:** a role with `rds-db:connect` for one database user can log in only as that user, and the database grants decide what it can do (the read-only user could not INSERT or DROP, the CRUD user could not CREATE or DROP). A role asking for another user was refused. A role carrying any of the three Annexure C policies could not log in at all, because none grants `rds-db:connect`.
- The "CRUB" role reset the master password and then logged in as the database owner and dropped the table.
- "Allowed" for delete and restore means AWS got past IAM and refused only for another reason (deletion protection, snapshot not found). Nothing was deleted or restored.

## Sessions and OIDC

- A session started without MFA is denied by a policy that requires `aws:MultiFactorAuthPresent`. This used an assumed-role session, which lacks the key the same way a SAML session does; SAML itself was not run.
- A deny on `aws:TokenIssueTime` cuts off older sessions at once while newer ones work. Deleting a role's permissions or the role itself also ends live sessions immediately. Removing someone from an identity provider group changes nothing in IAM, so their existing credentials last until they expire unless the role is revoked.
- OIDC (GitHub Actions as the issuer, the same AWS mechanism EKS pods and Azure DevOps use): a role pinned to the exact `sub` was assumed from the right branch and denied from another branch, another repository, and with the wrong audience. AWS refuses to create a GitHub trust policy with no `sub` or a bare wildcard. The token's `sub` carries numeric IDs (`repo:owner@id/name@id:...`), so a policy copied from an older guide never matches; take it from a real token.

## Microsoft Entra ID token

`real_entra_oidc_test.py` creates an Entra app registration, gets a real token for it with the Azure CLI (the signed-in user's token, no client secret), and tries it against roles that trust an IAM OIDC provider for the token's issuer. Entra can issue two token formats for the same app, and AWS treated them differently:

| | v1 token | v2 token |
|---|---|---|
| Issuer | `https://sts.windows.net/<tenant>/` | `https://login.microsoftonline.com/<tenant>/v2.0` |
| Audience | `api://<app id>` | `<app id>` |
| Role pinned to the exact `sub` and audience | **assumed** | rejected: `InvalidIdentityToken` |
| Role pinned to a different `sub` | denied | rejected: `InvalidIdentityToken` |
| Role with an audience condition only | created, and **assumed** | created, rejected |
| Token issued for another audience (Microsoft Graph) | rejected | rejected |

- AWS rejected every v2 token as "could not be validated", while the token itself looked normal (RS256, signing key published, issuer matching discovery). In earlier manual runs an explicit certificate thumbprint made no difference. Set the app to issue v1 tokens and test before relying on either format.
- Unlike GitHub, AWS accepts a trust policy for Entra that checks only the audience. Any user who can get a token for the app can then assume that role, so pin `sub`.
- The v1 `sub` is an identifier specific to the user and the app. The token also carried `amr` (`pwd`, `mfa`) and lived about 77 to 90 minutes.

## Not tested

- IAM Identity Center (the console is needed to enable it, and the test user has no `sso:*` permissions), SAML federation, SailPoint, Azure DevOps and EKS themselves, and Entra provisioning (SCIM). Entra tokens were tested only as a signed-in user's token, not for a service principal or managed identity.
- Other Regions and other accounts than the ones used, and SCP behaviour on principals other than the one exempt role.
- The tests show what the policies allow and deny, not whether an organisation's process (approvals, access reviews, SCIM timing) works.
