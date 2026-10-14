#!/usr/bin/env python3
"""Real calls to many AWS services under the SCP rules, without needing a second account.

real_scp_test.py attaches the SCPs in a real Organization, but a brand-new member account only
has ECR active for its first hours. This test uses an account where the common services are
already active: it puts each SCP's statements on a role as a PERMISSIONS BOUNDARY (plus an
allow-all, so only the SCP's own deny can matter) and makes real calls to KMS, S3, Lambda, SNS,
EC2, RDS, Systems Manager, DynamoDB, CloudFront, Route 53 and IAM. A boundary and an SCP both
filter permissions and both honour explicit denies, and a live service fills in
aws:RequestedRegion the same way for both. The one thing it does not prove is the Organizations
attachment itself, which real_scp_test.py covers.

A call counts as DENIED when AWS reports an explicit deny in the permissions boundary.
"allowed" means IAM let it through, even if the service then returned its own error (for example
a bucket that does not exist), because that error proves the request passed authorization.

Usage: AWS_PROFILE=<account where the services are active> python3 aws-validation/real_scp_boundary_test.py
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCP_DIR = HERE.parent / "required-scp"
PREFIX = "scp-boundary-test"
created = {"role": None, "policies": [], "buckets": []}
results = []
account = None


def aws(*args, env=None, ok_fail=False, region="eu-west-1"):
    cmd = ["aws", *args, "--region", region, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if ok_fail:
        return proc.returncode == 0, (proc.stdout if proc.returncode == 0 else proc.stderr)
    if proc.returncode:
        raise RuntimeError("aws %s failed: %s" % (" ".join(args[:2]), proc.stderr.strip()[:300]))
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def session_env():
    out = aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/%s" % (account, PREFIX),
              "--role-session-name", "scp-boundary")["Credentials"]
    env = {k: v for k, v in os.environ.items() if k != "AWS_PROFILE"}
    env.update(AWS_ACCESS_KEY_ID=out["AccessKeyId"], AWS_SECRET_ACCESS_KEY=out["SecretAccessKey"],
               AWS_SESSION_TOKEN=out["SessionToken"])
    return env


def call(env, region, *args):
    """'DENIED' for an explicit boundary deny, 'allowed' for anything else AWS answered after authorization."""
    ok, text = aws(*args, env=env, ok_fail=True, region=region)
    if ok:
        return "allowed"
    if "explicit deny in a permissions boundary" in text:
        return "DENIED"
    if "organizations" in args[0] and "You don't have permissions to access this resource" in text:
        return "DENIED"       # Organizations words its denials generically
    if "AccessDenied" in text or "UnauthorizedOperation" in text or "not authorized" in text:
        return "other denial: " + text.strip().splitlines()[-1][:90]
    return "allowed"      # a service-level error (not found, not subscribed...) comes after authorization


# (label, region, aws args). All are read-only or aimed at things that do not exist.
PROBES = [
    ("KMS list-keys", None, ["kms", "list-keys"]),
    ("Lambda list-functions", None, ["lambda", "list-functions"]),
    ("SNS list-topics", None, ["sns", "list-topics"]),
    ("EC2 describe-vpcs", None, ["ec2", "describe-vpcs"]),
    ("RDS describe-db-instances", None, ["rds", "describe-db-instances"]),
    ("Systems Manager describe-parameters", None, ["ssm", "describe-parameters"]),
    ("DynamoDB list-tables", None, ["dynamodb", "list-tables"]),
    ("CloudWatch Logs describe-log-groups", None, ["logs", "describe-log-groups"]),
]
GLOBAL_PROBES = [
    ("IAM list-roles", ["iam", "list-roles", "--max-items", "1"]),
    ("Route 53 list-hosted-zones", ["route53", "list-hosted-zones"]),
    ("CloudFront list-distributions", ["cloudfront", "list-distributions"]),
    ("S3 list-buckets (ListAllMyBuckets)", ["s3api", "list-buckets"]),
    ("Organizations list-roots", ["organizations", "list-roots"]),
]


def s3_create_bucket(env, region, tag):
    """S3 answers NoSuchBucket before it authorizes, so creating a bucket is the probe that works for S3."""
    name = "%s-%s-%s" % (PREFIX, tag, account)
    args = ["s3api", "create-bucket", "--bucket", name]
    if region != "us-east-1":
        args += ["--create-bucket-configuration", "LocationConstraint=" + region]
    ok, text = aws(*args, env=env, ok_fail=True, region=region)
    if ok:
        created["buckets"].append(name)
        return "allowed"
    if "explicit deny in a permissions boundary" in text:
        return "DENIED"
    return "other: " + text.strip().splitlines()[-1][:90]


def set_boundary(name, scp_file):
    doc = json.loads((SCP_DIR / scp_file).read_text())
    doc["Statement"].append({"Sid": "AllowAll", "Effect": "Allow", "Action": "*", "Resource": "*"})
    arn = aws("iam", "create-policy", "--policy-name", name, "--policy-document", json.dumps(doc))["Policy"]["Arn"]
    created["policies"].append(arn)
    aws("iam", "put-role-permissions-boundary", "--role-name", PREFIX, "--permissions-boundary", arn)
    return arn


def settle(canary_args, want, seconds=90):
    """IAM changes are quick but not instant; wait until a canary call shows the new boundary."""
    end = time.time() + seconds
    while time.time() < end:
        if call(session_env(), "us-east-1", *canary_args) == want:
            return
        time.sleep(5)
    raise RuntimeError("the boundary did not take effect")


def run():
    global account
    account = aws("sts", "get-caller-identity")["Account"]
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % account}, "Action": "sts:AssumeRole"}]})
    aws("iam", "create-role", "--role-name", PREFIX, "--assume-role-policy-document", trust)
    created["role"] = PREFIX
    aws("iam", "attach-role-policy", "--role-name", PREFIX, "--policy-arn", "arn:aws:iam::aws:policy/AdministratorAccess")

    for variant, scp_file, regional_want, global_want in (
            ("main SCP", "scp-restrict-to-eu-west-1.json", "DENIED", "allowed"),
            ("strict SCP", "scp-strict-all-services.json", "DENIED", "DENIED")):
        print(variant)
        set_boundary("%s-%s" % (PREFIX, variant.split()[0]), scp_file)
        time.sleep(10)
        settle(["ec2", "describe-vpcs"], "DENIED")
        env = session_env()
        tag = variant.split()[0]
        results.append(("%s: S3 create-bucket in eu-west-1" % variant, s3_create_bucket(env, "eu-west-1", tag), "allowed"))
        results.append(("%s: S3 create-bucket in us-east-1" % variant, s3_create_bucket(env, "us-east-1", tag), regional_want))
        for label, _, args in PROBES:
            results.append(("%s: %s in eu-west-1" % (variant, label), call(env, "eu-west-1", *args), "allowed"))
            results.append(("%s: %s in us-east-1" % (variant, label), call(env, "us-east-1", *args), regional_want))
        results.append(("%s: EC2 describe-vpcs in ap-south-1" % variant, call(env, "ap-south-1", "ec2", "describe-vpcs"), regional_want))
        results.append(("%s: SNS list-topics in eu-central-1" % variant, call(env, "eu-central-1", "sns", "list-topics"), regional_want))
        for label, args in GLOBAL_PROBES:
            results.append(("%s: %s (global)" % (variant, label), call(env, "us-east-1", *args), global_want))


def cleanup():
    print("\ncleaning up...")
    for bucket in created["buckets"]:
        aws("s3api", "delete-bucket", "--bucket", bucket, ok_fail=True)
    if created["role"]:
        aws("iam", "delete-role-permissions-boundary", "--role-name", PREFIX, ok_fail=True)
        aws("iam", "detach-role-policy", "--role-name", PREFIX,
            "--policy-arn", "arn:aws:iam::aws:policy/AdministratorAccess", ok_fail=True)
        aws("iam", "delete-role", "--role-name", PREFIX, ok_fail=True)
    for arn in created["policies"]:
        aws("iam", "delete-policy", "--policy-arn", arn, ok_fail=True)
    print("cleanup done")


def main():
    try:
        run()
    finally:
        cleanup()
    print("\n%-72s %-14s %s" % ("check", "result", "expected"))
    bad = 0
    for label, got, want in results:
        bad += got != want
        print("[%s] %-67s %-14s %s" % ("ok  " if got == want else "FAIL", label, got, want))
    print("\n%s (%d checks)" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad, len(results)))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
