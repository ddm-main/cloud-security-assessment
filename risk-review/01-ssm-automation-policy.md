# Review 1: SSM automation policy (Annexure A / B)

**Use case:** deploy commands and applications with Systems Manager from an Azure DevOps pipeline, into three AWS accounts. The policy under review is the one "to attach to ssm execution roles".

## What the diagram shows (Annexure B)

- A user triggers Azure DevOps. The agent runs in an **EKS Fargate pod using IRSA** and assumes **`systemsmanager_automation_azure_role`** in each of Account 1, 2 and 3.
- In each account, Systems Manager then assumes **`automation_excution_role`** (spelled "excution" in the diagram) and acts on one EC2 instance. Only Account 1 carries the label "Start SSM Automation".
- Not shown: which account hosts EKS, how the pod's IRSA role is trusted by the three accounts, any network path, any log or artifact bucket (although the policy grants S3 and CloudWatch Logs access), and how many instances each account has (the policy targets `instance/*`).

So there are **two roles per account**: a *dispatcher* that only starts the automation (the pod's `..._azure_role`) and an *execution role* that Systems Manager assumes to do the work. Annexure A is titled as the execution role's policy but also reads like a dispatcher policy (it has `GetAutomationExecution` but no `StartAutomationExecution`). Section S10 deals with that.

## Verdict

**Do not approve as written.** The intent is good (explicit Deny list, `eu-west-1` scoping, tag-gated targets, no `StartSession`), but the policy has one **privilege-escalation path**, grants **arbitrary root-level code execution**, and has **several defects** that suggest it was not validated. Details, mitigations and outcomes follow; hardened policies for the two roles are in [`ssm-execution-role-policy.json`](ssm-execution-role-policy.json) and [`ssm-dispatcher-role-policy.json`](ssm-dispatcher-role-policy.json), and the whole flow was run end to end on real instances.

## Risk register

| # | Finding | Severity |
|---|---|---|
| S1 | `ec2:CreateTags` is unconditioned, so the role can tag any instance `AutomationAllowed=true` and then run commands on it | **Critical** |
| S2 | `AWS-RunShellScript`/`RunPowerShellScript` = arbitrary command execution as root/SYSTEM; the tag condition is the only brake | **High** |
| S3 | `s3:GetObject`/`PutObject` on `arn:aws:s3:::*/*` (every bucket) | **High** |
| S4 | `customer-*` documents from a *different* account (`839864138277`) are trusted | **High** |
| S5 | `ec2:Start/Stop/RebootInstances` on every instance in the account, no tag condition | **Medium-High** |
| S6 | Blast radius: one pipeline/pod compromise reaches 3 accounts; trust policy and pipeline controls are not shown | **High** |
| S7 | Deny-list design and a control bypass (`StartSession` denied, `RunShellScript` allowed) | **Medium** |
| S8 | Read actions on `*` leak fleet inventory and command output | **Medium** |
| S9 | Policy is syntactically broken/inconsistent (account IDs, ARNs, empty statements) | **Medium** (process risk) |
| S10 | Policy does not match the stated use case ("Start SSM Automation") | **Medium** |
| S11 | No logging/detection requirements; no Region condition on `*` resources | **Medium** |

## Findings in detail

### S1: Self-service privilege escalation via `ec2:CreateTags` (Critical)
- **What:** `EC2ControlledActions` allows `ec2:CreateTags` on `instance/*`. `SSMSendCmdInstances` allows `SendCommand` only on instances tagged `AutomationAllowed=true` **and** `Application=Automated-Deployment-Dev`. Tags are the *only* authorisation boundary, and the role can write them.
- **Attack:** assume role, tag any instance (a database host, a bastion), run `AWS-RunShellScript` on it. The tag gate is decorative.
- **Mitigating controls:** remove `CreateTags` (tag via IaC instead). If it is needed, limit with `ec2:CreateAction`/`aws:TagKeys` so only *non-authorisation* keys can be set, and add an explicit **Deny** on writing `AutomationAllowed`/`Application`. Add an SCP denying tag changes to those keys except for a tagging-admin role. Alert on `CreateTags`/`DeleteTags` for these keys.
- **Outcome if unaddressed:** any holder of the role (or anyone who can run a pipeline) gets remote root on every instance in the account.
- **Tested on real instances:** with the account ID typo from S9 corrected, a role carrying the PDF policy tagged an untagged instance with the gate tags and then ran a command on it. The hardened policy denied the tagging. As printed, with the typo, the EC2 statement matches nothing and the same calls are denied (see [aws-validation](../aws-validation/README.md)).

### S2: Arbitrary command execution (High)
- **What:** `AWS-RunShellScript` and `AWS-RunPowerShellScript` run *any* string. Whoever controls the pipeline definition controls the command. `SendCommand` runs with the **instance profile's** permissions, so the real power is "everything the instance role can do" (lateral movement).
- **Mitigating controls:**
  - Replace generic run-script documents with **purpose-built, versioned, parameter-validated custom documents** (`Automated-Deployment-Dev` already exists; permit *only* that).
  - Pipeline: protected branches, required reviewers on pipeline YAML, Azure DevOps *Environments* with approvals/checks for prod, no pipeline edits from forks/PR builds.
  - Least-privilege **instance profiles**; enforce IMDSv2.
  - Command output to a KMS-encrypted bucket; alert on every `SendCommand` using the generic documents.
- **Outcome:** a malicious or careless pipeline change becomes a production code-execution event (malware, data theft, ransomware on tagged hosts).

### S3: `s3:*Object` on all buckets (High)
- **What:** `S3Objects` uses `arn:aws:s3:::*/*`. This covers every bucket in the account, and any cross-account bucket whose policy allows it. The sibling `S3Bucket` statement scopes `automated-deployment*` and shows the intent.
- **Abuse:** read secrets/backups/state files; `PutObject` to overwrite artifacts other systems deploy (supply-chain tampering), or **exfiltrate** to an attacker-owned bucket (`PutObject` accepts any destination).
- **Mitigations:** scope to `arn:aws:s3:::automated-deployment-*/deploy/*`; add `aws:ResourceAccount` condition; bucket policies deny non-VPCE / non-org principals; SSE-KMS with a key policy limited to this role; S3 data-event logging on those buckets.
- **Outcome:** data breach or tampering of build/deploy artifacts.

### S4: Cross-account `customer-*` documents (High)
- **What:** `SendCommand` is allowed on `arn:aws:ssm:eu-west-1:839864138277:document/customer-*`. That is a **different account** from the instances (`222222222222`) and uses a wildcard.
- **Abuse:** anyone who can create or modify a document called `customer-<anything>` in that account, or any document shared with this account, runs code on your instances. Documents can be updated after review (default-version change).
- **Mitigations:** confirm *who owns 839864138277* and why it's trusted. Pin explicit document names, call them by a fixed document version from the pipeline, share documents only to specific accounts, restrict `ssm:CreateDocument`/`UpdateDocument*` in the owning account, and monitor `ModifyDocumentPermission`.
- **Outcome:** third-party code execution (supply-chain compromise).

### S5: Unscoped instance power actions (Medium-High)
- **What:** `StartInstances/StopInstances/RebootInstances` on `instance/*`, no tag condition.
- **Outcome:** a bug or attacker can stop production instances (availability incident). **Fix:** add an `aws:ResourceTag/Application = Automated-Deployment-Dev` condition (not writable by the role, see S1); the execution-role policy drops `StopInstances` because a deployment does not need it.

### S6: Blast radius and trust (High)
- **What (Annexure B):** one EKS Fargate pod with IRSA assumes a role in **Accounts 1, 2 and 3**. A compromise of the agent pod, its service-account token, or the Azure DevOps project is a compromise of all three accounts. The role **trust policy** is not provided; it is the real control.
- **Mitigations:**
  - Trust policy conditions: the exact pod role ARN as the only principal (plus `aws:PrincipalOrgID`), and for IRSA the OIDC `sub` pinned to *that* namespace/service-account (`system:serviceaccount:<ns>:<sa>`) and `aud=sts.amazonaws.com`; never `StringLike *`.
  - **One role per account and per environment**, with *separate* pods/agent pools for prod vs non-prod. Do not reuse the same agent identity for dev and prod.
  - Short session duration (<=1 h), `sts:SourceIdentity`/session tags carrying pipeline and run ID for attribution.
  - Network: pod egress limited by security groups for pods/network policy; no shared pod for unrelated pipelines; ephemeral agents.
- **Outcome:** lateral movement across all accounts from one foothold; no attribution of who deployed what.
- **Tested with a real OIDC token** (GitHub Actions as the issuer; the same AWS mechanism EKS pods and Azure DevOps use, but not those products themselves): a role pinned to the exact `sub` was assumed from the right branch; the same token was denied by a role pinned to another repository, by the same role from a different branch, and with the wrong audience. AWS refuses to create a GitHub trust policy with no `sub` or with a bare wildcard, but other issuers may not get that protection. One trap: the token's `sub` can carry numeric IDs (`repo:owner@<id>/name@<id>:...`), so a policy copied from an older guide never matches. Take the subject from a real token (see [aws-validation](../aws-validation/README.md)).
- **Tested with a real Microsoft Entra ID token too:** AWS accepted the v1 token format and rejected the v2 format as "could not be validated". A role that checks only the audience was created and could be assumed by any user able to get a token for the app (AWS blocks that for GitHub but not for Entra), so pin `sub` for Entra as well.
- **Also:** the policy hard-codes the `Dev` document and one account ID, so *promotion to prod* will pressure someone to copy it with wildcards. Define per-environment policies up front.

### S7: Deny-list design and control bypass (Medium)
- **Good:** an explicit Deny is stronger than any allow, and `StartSession`/`ResumeSession` are blocked.
- **But:** (a) the Deny enumerates "bad" actions, so new/omitted ones fall through if any other policy (e.g. `AmazonSSMFullAccess`) is attached. Notably **absent**: `ssm:CreateDocument`, `DeleteDocument`, `CreateAssociation`, `StartAssociationsOnce`, `PutResourcePolicy`, `StartAutomationExecution`, `StopAutomationExecution`, `GetParameter*`, `CancelCommand`. (b) Blocking interactive sessions while allowing `RunShellScript` doesn't achieve the intent; the same shell is reachable through `SendCommand`.
- **Mitigation:** treat the *Allow* as the control (least privilege), keep a *short* Deny as a safety net, add a **permissions boundary** or SCP that denies `ssm:*` write actions outside this role.

### S8: Wildcard read access (Medium)
- `GetCommandInvocation`, `ListCommandInvocations`, `ListDocuments`, `DescribeInstanceInformation`, etc. on `*` expose the whole fleet inventory and **command output from other teams' runs**, which commonly contains secrets in stdout. Restrict to the same tagged instances/documents where the action supports resource-level permissions; scrub secrets from output (use SSM Parameter Store/Secrets Manager references, not literals); encrypt output.

### S9: Policy is defective as submitted (process risk)
- **Account IDs don't match:** `22222222222` (11 digits) vs `222222222222`. IAM Access Analyzer's `validate-policy` reports the 11-digit one as an error (`INVALID_ARN_ACCOUNT`, `ARN_ACCOUNT_NOT_ALLOWED`), but IAM itself still accepts the policy (tested), so it can be attached and the statement silently matches nothing.
- **Malformed bucket ARN:** `arn:aws:s3::: automated-deployment*` has a **space**. Access Analyzer does not flag it, but no bucket name can start with a space, so the statement can never match and `GetBucketLocation` silently does nothing.
- **Log ARN:** `PutLogEvents` needs `...log-group:/aws/ssm/deployment/*:*` (log-stream suffix). The log group is also in account `839864138277`, not the deploying account. A role cannot reach a log group in another account through its own-account permissions, so either the writes fail or there is a cross-account setup that is not documented. Confirm which.
- **JSON structure:** as it appears in the PDF the policy has empty `{}` statements and missing commas, which IAM would reject. This may only be a formatting problem in the document, but the submitted text should be valid JSON.
- **Mitigation:** require **IAM Access Analyzer `validate-policy`**, `cfn-lint`/`checkov`, and a deployment test in a sandbox before any security approval; manage the policy in Terraform with PR review.
- **Outcome:** failures get "fixed" under time pressure by widening permissions; the unnoticed typos above change behaviour silently.

### S10: Two roles are conflated, and the diagram's role name is misspelled (Medium)
- **What:** the diagram has a dispatcher (`systemsmanager_automation_azure_role`, assumed by the pod) and an execution role (assumed by Systems Manager). The policy contains neither `ssm:StartAutomationExecution` nor `iam:PassRole`, so as written it cannot start the "Start SSM Automation" step, and it mixes permissions that belong on different roles.
- **Split:**
  - *Dispatcher:* `StartAutomationExecution` on the one approved runbook, read access to executions, and `iam:PassRole` to the execution role only (`iam:PassedToService = ssm.amazonaws.com`). It must **not** be able to run commands, tag instances or start sessions itself.
  - *Execution role:* what the runbook's steps need (run the approved document on tagged instances, limited S3 and logs), with the tag gate, and trusted **only** by `ssm.amazonaws.com` from this account's automation executions (`aws:SourceAccount` and `aws:SourceArn`), which prevents another account's Systems Manager from using the role.
- **AWS checks two resources for `StartAutomationExecution`:** the runbook as `document/<name>` and the new execution as `automation-execution/*`. An `automation-definition/...` ARN does not work.
- **Spelling:** the diagram writes `automation_excution_role`. Whatever name is really deployed must be the one in the dispatcher's `PassRole` ARN and in the trust relationships. The policy files here use `automation_execution_role`, which will not match a role that was actually created with the diagram's spelling.
- **Tested end to end on real instances** (see [aws-validation](../aws-validation/README.md)): the dispatcher started the runbook and the approved command ran on the tagged instance; on an untagged instance the execution failed with an access-denied error from the tag condition; passing any other role was denied; starting a different runbook, running `SendCommand` directly, starting a session and tagging an instance were all denied for the dispatcher; and an ordinary principal could not assume the execution role.

### S11: Detection and Region (Medium)
- Add `aws:RequestedRegion = eu-west-1` conditions to `Resource:"*"` statements (or rely on the Q3 SCP).
- Detection: CloudTrail + EventBridge rules for `SendCommand` with generic documents, `CreateTags` of the gate keys, `PutObject` to unexpected buckets; SSM command logging to CloudWatch/S3; GuardDuty; Config rule for untagged-but-targeted instances.

## What is good (keep)
- Explicit Deny on high-risk SSM mutations; no `ssm:*`.
- Regional scoping of documents and instances; tag-gated `SendCommand` (once S1 is fixed).
- IRSA instead of static keys; separate role per account; "Dev" naming intent.

## Possible outcomes summary

| Scenario | Today | After mitigation |
|---|---|---|
| Malicious PR edits pipeline YAML | Root shell on any tagged (or self-tagged) instance | Needs reviewer approval; limited to one parameterised document |
| Agent pod compromised | Lateral move into 3 accounts | Per-account/env roles, pinned OIDC `sub`, 1 h sessions, alerts |
| Operator typo / bug | Stops/reboots arbitrary instances; writes any S3 bucket | Scoped by non-writable tags and bucket prefix |
| Audit asks "who ran what?" | Shared role, no attribution | `SourceIdentity` + run ID + CloudTrail/SSM logs |

## Recommended approval conditions
1. Remove or lock down `CreateTags` (S1). 2. Replace generic run-script documents with named custom documents (S2). 3. Scope S3 and add KMS (S3). 4. Justify or drop `customer-*` cross-account docs (S4). 5. Fix all syntax/ARN defects and validate (S9). 6. Provide and review the **trust policy**, per-env roles and logging design (S6, S11). Re-review after resubmission.
