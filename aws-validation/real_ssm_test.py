#!/usr/bin/env python3
"""Test the SSM policies against real EC2 instances, Systems Manager and S3.

It creates: two small EC2 instances (one tagged for automation, one not), an instance role,
two SSM documents, two S3 buckets and two test roles that carry the policy under test.
Then it makes real API calls as each role and compares the outcome with what the review says.
Everything is deleted at the end, even if a check fails. Cost is a few cents.

Usage: AWS_PROFILE=<admin profile> python3 aws-validation/real_ssm_test.py
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REGION = "eu-west-1"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PREFIX = "ssm-policy-test"

ACCOUNT = None
created = {"instances": [], "roles": [], "profile": None, "docs": [], "buckets": []}
results = []


def aws(*args, env=None, ok_fail=False):
    """Run the AWS CLI, return parsed JSON (or text). With ok_fail, return (ok, text)."""
    cmd = ["aws", *args, "--region", REGION, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if ok_fail:
        return proc.returncode == 0, (proc.stdout if proc.returncode == 0 else proc.stderr)
    if proc.returncode:
        raise RuntimeError("aws %s failed: %s" % (" ".join(args[:2]), proc.stderr.strip()[:300]))
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def outcome(ok, text):
    """Reduce a CLI result to OK, AccessDenied, or the AWS error code."""
    if ok:
        return "OK"
    for code in ("AccessDenied", "UnauthorizedOperation", "AccessDeniedException"):
        if code in text:
            return "AccessDenied"
    start = text.find("(")
    return text[start + 1:text.find(")", start)] if start != -1 else text.strip()[:60]


def wait_for(description, check, timeout=420, step=10):
    end = time.time() + timeout
    while time.time() < end:
        if check():
            return
        time.sleep(step)
    raise RuntimeError("timed out waiting for " + description)


def policy_text(path, replacements):
    text = Path(path).read_text()
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def setup():
    global ACCOUNT
    ACCOUNT = aws("sts", "get-caller-identity")["Account"]
    acct = ACCOUNT
    print("account", acct)

    deploy_bucket = "%s-deploy-%s" % (PREFIX, acct)
    other_bucket = "%s-other-%s" % (PREFIX, acct)
    for bucket in (deploy_bucket, other_bucket):
        aws("s3api", "create-bucket", "--bucket", bucket,
            "--create-bucket-configuration", "LocationConstraint=" + REGION)
        created["buckets"].append(bucket)
    for bucket, key in ((deploy_bucket, "deploy/app.txt"), (other_bucket, "secret.txt")):
        Path("/tmp/%s-body" % PREFIX).write_text("test object\n")
        aws("s3api", "put-object", "--bucket", bucket, "--key", key, "--body", "/tmp/%s-body" % PREFIX)

    # instance role so the SSM agent can register
    trust_ec2 = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
    role = PREFIX + "-instance-role"
    aws("iam", "create-role", "--role-name", role, "--assume-role-policy-document", trust_ec2)
    created["roles"].append(role)
    aws("iam", "attach-role-policy", "--role-name", role,
        "--policy-arn", "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
    aws("iam", "create-instance-profile", "--instance-profile-name", role)
    created["profile"] = role
    aws("iam", "add-role-to-instance-profile", "--instance-profile-name", role, "--role-name", role)

    ami = aws("ssm", "get-parameter", "--name",
              "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
    subnet = aws("ec2", "describe-subnets", "--filters", "Name=default-for-az,Values=true")["Subnets"][0]["SubnetId"]

    def launch(name, extra_tags):
        tags = [{"Key": "Name", "Value": name}, {"Key": "project", "Value": PREFIX}] + extra_tags
        tag_arg = "ResourceType=instance,Tags=[" + ",".join(
            "{Key=%s,Value=%s}" % (t["Key"], t["Value"]) for t in tags) + "]"
        for attempt in range(8):    # the new instance profile takes a few seconds to be usable
            ok, text = aws("ec2", "run-instances", "--image-id", ami, "--instance-type", "t3.micro",
                           "--subnet-id", subnet, "--iam-instance-profile", "Name=" + role,
                           "--metadata-options", "HttpTokens=required", "--tag-specifications", tag_arg,
                           "--count", "1", ok_fail=True)
            if ok:
                instance_id = json.loads(text)["Instances"][0]["InstanceId"]
                created["instances"].append(instance_id)
                return instance_id
            time.sleep(8)
        raise RuntimeError("could not launch instance: " + text[:200])

    tagged = launch(PREFIX + "-tagged", [{"Key": "AutomationAllowed", "Value": "true"},
                                         {"Key": "Application", "Value": "Automated-Deployment-Dev"}])
    untagged = launch(PREFIX + "-untagged", [])
    print("instances", tagged, untagged)

    # documents: one Command document, one Automation runbook
    command_doc = {"schemaVersion": "2.2", "description": "test deployment", "mainSteps": [
        {"action": "aws:runShellScript", "name": "deploy", "inputs": {"runCommand": ["echo deployed by the approved document"]}}]}
    auto_doc = {"schemaVersion": "0.3", "description": "test runbook", "mainSteps": [
        {"name": "wait", "action": "aws:sleep", "inputs": {"Duration": "PT1S"}}]}
    Path("/tmp/%s-cmd.json" % PREFIX).write_text(json.dumps(command_doc))
    Path("/tmp/%s-auto.json" % PREFIX).write_text(json.dumps(auto_doc))
    aws("ssm", "create-document", "--name", "Deploy-Cmd", "--document-type", "Command",
        "--content", "file:///tmp/%s-cmd.json" % PREFIX)
    created["docs"].append("Deploy-Cmd")
    aws("ssm", "create-document", "--name", "Deploy-Auto", "--document-type", "Automation",
        "--content", "file:///tmp/%s-auto.json" % PREFIX)
    created["docs"].append("Deploy-Auto")

    # the test roles carry the policies, with the account, document and bucket names pointed at what exists
    # the runbook name must be swapped before the command document name, which is a prefix of it
    names = [("document/Automated-Deployment-Dev-Runbook", "document/Deploy-Auto"),
             ("document/Automated-Deployment-Dev", "document/Deploy-Cmd"),
             ("arn:aws:s3:::automated-deployment-dev", "arn:aws:s3:::" + deploy_bucket)]
    swaps = [("222222222222", acct)] + names
    trust_self = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % acct}, "Action": "sts:AssumeRole"}]})
    policies = {"pdf": HERE / "annexure-a-account-fixed.json",
                "hardened": ROOT / "risk-review" / "ssm-execution-role-policy.json"}
    for label, path in policies.items():
        name = "%s-%s" % (PREFIX, label)
        aws("iam", "create-role", "--role-name", name, "--assume-role-policy-document", trust_self)
        created["roles"].append(name)
        aws("iam", "put-role-policy", "--role-name", name, "--policy-name", "under-test",
            "--policy-document", policy_text(path, swaps))

    # the policy exactly as printed in the PDF (11-digit account ID): does IAM take it, and what does it allow?
    printed_role = PREFIX + "-printed"
    aws("iam", "create-role", "--role-name", printed_role, "--assume-role-policy-document", trust_self)
    created["roles"].append(printed_role)
    ok, text = aws("iam", "put-role-policy", "--role-name", printed_role, "--policy-name", "under-test",
                   "--policy-document", policy_text(HERE / "annexure-a-as-printed.json", names), ok_fail=True)
    # Access Analyzer reports the 11-digit account ID as an error, but IAM itself takes the policy
    results.append(("IAM accepts the PDF policy with the 11-digit account ID", "accepted" if ok else "rejected", "accepted"))

    print("waiting for the instances to register with Systems Manager...")

    def registered():
        info = aws("ssm", "describe-instance-information")["InstanceInformationList"]
        online = {i["InstanceId"] for i in info if i["PingStatus"] == "Online"}
        return tagged in online and untagged in online
    wait_for("instances to register with SSM", registered)
    time.sleep(20)   # let the new roles propagate
    return dict(tagged=tagged, untagged=untagged, deploy_bucket=deploy_bucket, other_bucket=other_bucket)


def assume(role):
    out = aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/%s" % (ACCOUNT, role),
              "--role-session-name", "policy-test")["Credentials"]
    env = {k: v for k, v in os.environ.items() if k not in ("AWS_PROFILE",)}
    env.update(AWS_ACCESS_KEY_ID=out["AccessKeyId"], AWS_SECRET_ACCESS_KEY=out["SecretAccessKey"],
               AWS_SESSION_TOKEN=out["SessionToken"])
    return env


def dry_run(command, instance, env):
    """AWS answers DryRunOperation when the call would have been allowed."""
    ok, text = aws("ec2", command, "--instance-ids", instance, "--dry-run", env=env, ok_fail=True)
    if "UnauthorizedOperation" in text:
        return "AccessDenied"
    return "allowed" if "DryRunOperation" in text else outcome(ok, text)


def run_printed(env, ctx):
    """The policy as printed: its EC2 statement names a non-existent 11-digit account, so it matches nothing."""
    u = ctx["untagged"]
    ok, text = aws("ec2", "create-tags", "--resources", u, "--tags", "Key=AutomationAllowed,Value=true", env=env, ok_fail=True)
    results.append(("printed  CreateTags on an instance in this account", outcome(ok, text), "AccessDenied"))
    results.append(("printed  StopInstances (dry run)", dry_run("stop-instances", u, env), "AccessDenied"))


def run_role(label, env, ctx, expect):
    """expect maps case name -> (expected for this role)."""
    t, u = ctx["tagged"], ctx["untagged"]
    sc = lambda doc, inst: aws("ssm", "send-command", "--document-name", doc, "--instance-ids", inst,
                               env=env, ok_fail=True)
    cases = []

    ok, text = sc("AWS-RunShellScript", t)
    cases.append(("SendCommand AWS-RunShellScript to the tagged instance", outcome(ok, text)))

    ok, text = sc("Deploy-Cmd", t)
    cases.append(("SendCommand the approved document to the tagged instance", outcome(ok, text)))
    if ok:
        command_id = json.loads(text)["Command"]["CommandId"]
        output = None
        for _ in range(20):
            time.sleep(5)
            done, text2 = aws("ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", t,
                              env=env, ok_fail=True)
            if done and json.loads(text2)["Status"] in ("Success", "Failed"):
                output = json.loads(text2)["StandardOutputContent"].strip()
                break
        cases.append(("  ...and the command really ran on the instance",
                      "ran" if output == "deployed by the approved document" else "no output"))

    ok, text = sc("Deploy-Cmd", u)
    cases.append(("SendCommand the approved document to the UNTAGGED instance", outcome(ok, text)))

    ok, text = sc("arn:aws:ssm:eu-west-1:839864138277:document/customer-evil", t)
    outcome_text = outcome(ok, text)
    cases.append(("SendCommand a customer-* document owned by another account",
                  "authorised" if outcome_text in ("OK", "InvalidDocument") else outcome_text))

    ok, text = aws("ec2", "create-tags", "--resources", u, "--tags", "Key=AutomationAllowed,Value=true",
                   "Key=Application,Value=Automated-Deployment-Dev", env=env, ok_fail=True)
    cases.append(("CreateTags: tag the untagged instance as automation-allowed", outcome(ok, text)))

    ok, text = sc("Deploy-Cmd", u)
    cases.append(("SendCommand to that instance after tagging it", outcome(ok, text)))

    ok, text = aws("s3api", "get-object", "--bucket", ctx["other_bucket"], "--key", "secret.txt",
                   "/tmp/%s-dl" % PREFIX, env=env, ok_fail=True)
    cases.append(("s3 GetObject from an unrelated bucket", outcome(ok, text)))
    ok, text = aws("s3api", "get-object", "--bucket", ctx["deploy_bucket"], "--key", "deploy/app.txt",
                   "/tmp/%s-dl" % PREFIX, env=env, ok_fail=True)
    cases.append(("s3 GetObject from the deploy bucket", outcome(ok, text)))

    ok, text = aws("ssm", "start-session", "--target", t, env=env, ok_fail=True)
    cases.append(("StartSession (interactive shell)", "AccessDenied" if "AccessDenied" in text else outcome(ok, text)))

    ok, text = aws("ssm", "start-automation-execution", "--document-name", "Deploy-Auto", env=env, ok_fail=True)
    cases.append(("StartAutomationExecution on the approved runbook", outcome(ok, text)))

    ok, text = aws("ssm", "start-automation-execution", "--document-name", "AWS-RestartEC2Instance",
                   "--parameters", "InstanceId=" + t, env=env, ok_fail=True)
    cases.append(("StartAutomationExecution on another runbook (AWS-owned)", outcome(ok, text)))

    cases.append(("StopInstances (dry run)", dry_run("stop-instances", t, env)))
    cases.append(("StartInstances (dry run) on the tagged instance", dry_run("start-instances", t, env)))
    cases.append(("StartInstances (dry run) on the UNTAGGED instance", dry_run("start-instances", u, env)))

    for name, got in cases:
        want = expect.get(name)
        results.append(("%-8s %s" % (label, name), got, want))


def cleanup():
    print("\ncleaning up...")
    acct = ACCOUNT
    def quiet(*args):
        aws(*args, ok_fail=True)
    if created["instances"]:
        quiet("ec2", "terminate-instances", "--instance-ids", *created["instances"])
    for doc in created["docs"]:
        quiet("ssm", "delete-document", "--name", doc, "--force")
    for bucket in created["buckets"]:
        quiet("s3", "rm", "s3://" + bucket, "--recursive")
        quiet("s3api", "delete-bucket", "--bucket", bucket)
    for role in created["roles"]:
        ok, text = aws("iam", "list-role-policies", "--role-name", role, ok_fail=True)
        for name in (json.loads(text)["PolicyNames"] if ok else []):
            quiet("iam", "delete-role-policy", "--role-name", role, "--policy-name", name)
        ok, text = aws("iam", "list-attached-role-policies", "--role-name", role, ok_fail=True)
        for p in (json.loads(text)["AttachedPolicies"] if ok else []):
            quiet("iam", "detach-role-policy", "--role-name", role, "--policy-arn", p["PolicyArn"])
    if created["profile"]:
        quiet("iam", "remove-role-from-instance-profile", "--instance-profile-name", created["profile"],
              "--role-name", created["profile"])
        quiet("iam", "delete-instance-profile", "--instance-profile-name", created["profile"])
    for role in created["roles"]:
        quiet("iam", "delete-role", "--role-name", role)
    if created["instances"]:
        wait_for("instances to terminate", lambda: all(
            i["State"]["Name"] == "terminated" for r in aws("ec2", "describe-instances", "--instance-ids",
                                                           *created["instances"])["Reservations"] for i in r["Instances"]),
                 timeout=300)
    print("cleanup done")


EXPECT_HARDENED = {
    "SendCommand AWS-RunShellScript to the tagged instance": "AccessDenied",
    "SendCommand the approved document to the tagged instance": "OK",
    "  ...and the command really ran on the instance": "ran",
    "SendCommand the approved document to the UNTAGGED instance": "AccessDenied",
    "SendCommand a customer-* document owned by another account": "AccessDenied",
    "CreateTags: tag the untagged instance as automation-allowed": "AccessDenied",
    "SendCommand to that instance after tagging it": "AccessDenied",
    "s3 GetObject from an unrelated bucket": "AccessDenied",
    "s3 GetObject from the deploy bucket": "OK",
    "StartSession (interactive shell)": "AccessDenied",
    "StartAutomationExecution on the approved runbook": "AccessDenied",
    "StartAutomationExecution on another runbook (AWS-owned)": "AccessDenied",
    "StopInstances (dry run)": "AccessDenied",
    "StartInstances (dry run) on the tagged instance": "allowed",
    "StartInstances (dry run) on the UNTAGGED instance": "AccessDenied",
}
EXPECT_PDF = {
    "SendCommand AWS-RunShellScript to the tagged instance": "OK",
    "SendCommand the approved document to the tagged instance": "OK",
    "  ...and the command really ran on the instance": "ran",
    "SendCommand the approved document to the UNTAGGED instance": "AccessDenied",
    "SendCommand a customer-* document owned by another account": "authorised",
    "CreateTags: tag the untagged instance as automation-allowed": "OK",
    "SendCommand to that instance after tagging it": "OK",
    "s3 GetObject from an unrelated bucket": "OK",
    "s3 GetObject from the deploy bucket": "OK",
    "StartSession (interactive shell)": "AccessDenied",
    "StartAutomationExecution on the approved runbook": "AccessDenied",
    "StartAutomationExecution on another runbook (AWS-owned)": "AccessDenied",
    "StopInstances (dry run)": "allowed",
    "StartInstances (dry run) on the tagged instance": "allowed",
    "StartInstances (dry run) on the UNTAGGED instance": "allowed",
}


def main():
    try:
        ctx = setup()
        # hardened first: the PDF run re-tags the untagged instance, which would change the later results
        run_role("hardened", assume(PREFIX + "-hardened"), ctx, EXPECT_HARDENED)
        run_role("pdf", assume(PREFIX + "-pdf"), ctx, EXPECT_PDF)
        run_printed(assume(PREFIX + "-printed"), ctx)
    finally:
        cleanup()

    print("\n%-84s %-14s %s" % ("check", "result", "expected"))
    bad = 0
    for name, got, want in results:
        flag = "ok  " if got == want else "FAIL"
        bad += got != want
        print("[%s] %-79s %-14s %s" % (flag, name, got, want))
    print("\n%s" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
