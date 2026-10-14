# Question 3: SCP to restrict AWS to eu-west-1

Three policy files, from the one I would deploy to the most literal:

| File | What it does | Use it when |
|---|---|---|
| [scp-restrict-to-eu-west-1.json](scp-restrict-to-eu-west-1.json) | Denies everything outside eu-west-1 except a list of global services | **Recommended.** Works in a real organization without breaking IAM, STS, CloudFront, Route 53 or billing |
| [scp-restrict-to-eu-west-1-with-breakglass.json](scp-restrict-to-eu-west-1-with-breakglass.json) | Same, plus two named admin roles are exempt | You want an emergency path |
| [scp-strict-all-services.json](scp-strict-all-services.json) | Denies **every** action outside eu-west-1, no exceptions | The task is read literally as "all services". Test it in a sandbox first, because it will block global services |

## How I approached it

The SCP is one Deny statement: deny every action when `aws:RequestedRegion` is anything other than `eu-west-1`, except for a short list of global services.

```
Effect:    Deny
NotAction: [global services...]
Condition: StringNotEquals { aws:RequestedRegion: "eu-west-1" }
```

- I used Deny with `NotAction` rather than an allow list. A Deny cannot be overridden by any IAM policy in the member account, and new AWS services are covered automatically. Only the exceptions have to be listed.
- The exceptions are needed because some services are not regional (IAM, Route 53, CloudFront, Organizations, billing, support, WAF for CloudFront) or are only served from us-east-1. Without the exceptions the console, IAM, billing and CloudFront would stop working.
- `StringNotEquals` with one value blocks every other Region, including the opt-in ones.
- A literal `Action: "*"` deny with no exceptions is the closest match to the wording of the task, and it is included as `scp-strict-all-services.json`. It breaks IAM, STS, CloudFront, Route 53 and billing, because those are served from us-east-1, so I recommend the exception list for a real deployment.

| Exempted actions | Reason |
|---|---|
| `iam`, `sts`, `organizations`, `account` | Global control planes (use the regional STS endpoint anyway) |
| `route53`, `route53domains`, `cloudfront`, `waf`, `wafv2`, `shield`, `fms`, `globalaccelerator`, `acm` | Global edge and DNS services. CloudFront certificates must be in us-east-1, which is why `acm` is listed |
| `budgets`, `ce`, `cur`, `billing`, `aws-portal`, `consolidatedbilling`, `invoicing`, `payments`, `tax`, `freetier`, `pricing` | Billing and cost services, served from us-east-1 |
| `support`, `health`, `trustedadvisor` | Served from us-east-1 |
| `directconnect` | Direct Connect gateways are global |
| `ec2:DescribeRegions` | Needed by the console and SDKs to list Regions |
| `s3:ListAllMyBuckets`, `s3:*AccountPublic*`, `s3:*MultiRegionAccessPoint*` | Account-level S3 calls that are not tied to a bucket Region |

I left out `kms`, `config` and `cloudtrail` on purpose, so nobody can create keys or trails in a Region nobody is watching. If a real dependency turns up, add them back.

## Deployment

1. In the management account, make sure SCPs are enabled and `FullAWSAccess` is still attached. SCPs only filter permissions, they never grant them.
2. Create the policy:
   ```bash
   aws organizations create-policy \
     --name RestrictToEuWest1 \
     --type SERVICE_CONTROL_POLICY \
     --description "Deny regional actions outside eu-west-1" \
     --content file://scp-restrict-to-eu-west-1.json
   ```
3. Attach it to a sandbox OU first:
   ```bash
   aws organizations attach-policy --policy-id p-xxxxxxxx --target-id ou-xxxx-xxxxxxxx
   ```
4. Test from an account in that OU:
   ```bash
   aws ec2 describe-vpcs --region eu-west-1     # works
   aws ec2 describe-vpcs --region us-east-1     # AccessDenied, explicit deny in a service control policy
   aws iam list-roles                           # works (global)
   ```
   Then look in CloudTrail for `AccessDenied` events caused by the SCP and check that none of them are real workloads.
5. Roll it out OU by OU (dev, test, prod), not at the root in one go.
6. Rollback is `aws organizations detach-policy` with the same IDs. It takes effect straight away and changes no resources.
7. Keep the JSON in git and deploy it through Terraform or CloudFormation with a reviewed pull request. Alert on `organizations:DetachPolicy` and `UpdatePolicy`.

## Things to check first

- SCPs do not apply to the management account or to service-linked roles, so keep workloads out of the management account.
- IAM Identity Center is regional. If the instance is not in eu-west-1, add `sso:*`, `sso-directory:*` and `identitystore:*` to `NotAction`.
- The org CloudTrail, GuardDuty, Security Hub and Config aggregators need to live in eu-west-1 as well.
- Features that only exist in us-east-1 will be blocked, for example Lambda@Edge and ECR Public.
- This controls API calls, not data location. Global services such as CloudFront can still move data, so pair it with a data residency policy.
- As extra protection, disable the Regions you don't use (`aws account disable-region`). An SCP can be changed later, a disabled Region cannot be used.

## Validation done

All three policy files were checked with AWS IAM Access Analyzer (`aws accessanalyzer validate-policy --policy-type SERVICE_CONTROL_POLICY`) and returned no errors, warnings or suggestions. The same command correctly rejects a policy with a mistyped condition operator, so a clean result is meaningful.

They were then tested for real:

- **Attached in a real AWS Organization** and probed from a member account (`aws-validation/real_scp_test.py`, 15 checks), including the break-glass exemption and a control role that is not exempt.
- **Many services** (`aws-validation/real_scp_boundary_test.py`, 50 checks): a brand-new member account only has a few services active at first, so the SCP rules were put on a role as a permissions boundary and tested with real calls to KMS, S3, Lambda, SNS, EC2, RDS, Systems Manager, DynamoDB, CloudWatch Logs, CloudFront, Route 53, IAM and Organizations. A boundary and an SCP both filter permissions and both honour explicit denies.

Results are in [../aws-validation](../aws-validation/README.md). In short: the main SCP denies regional calls outside eu-west-1 and keeps the global services working, and the strict SCP also denies IAM, Route 53, CloudFront and Organizations.
