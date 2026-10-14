#!/usr/bin/env python3
"""Run the Annexure B flow end to end with the split policies, on real instances.

Annexure B shows two roles in each target account:
  * systemsmanager_automation_azure_role: assumed by the pipeline pod, only starts the automation
  * automation_excution_role (sic): assumed by Systems Manager, does the work on the instances

risk-review/ssm-dispatcher-role-policy.json and risk-review/ssm-execution-role-policy.json are the
hardened policies for those two roles. This test creates both roles (the execution role trusts only
ssm.amazonaws.com, from this account's automation executions), a runbook that runs the approved
command document, and two instances (one tagged for automation, one not). It then starts the
automation as the dispatcher and checks what really happens. The pipeline's own identity (Azure
DevOps, the pod's IRSA role) is replaced by a plain assume-role into the dispatcher; the OIDC part
is covered by real_oidc_trust_test.py.

Everything created is deleted at the end. A few cents; about 8 minutes.

Usage: AWS_PROFILE=<admin profile> python3 aws-validation/real_ssm_e2e_test.py
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REGION = "eu-west-1"
HERE = Path(__file__).resolve().parent
POLICY_DIR = HERE.parent / "risk-review"
PREFIX = "ssm-e2e"
created = {"instances": [], "roles": [], "profile": None, "docs": []}
results = []
ACCOUNT = None


def aws(*args, env=None, ok_fail=False):
    cmd = ["aws", *args, "--region", REGION, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if ok_fail:
        return proc.returncode == 0, (proc.stdout if proc.returncode == 0 else proc.stderr)
    if proc.returncode:
        raise RuntimeError("aws %s failed: %s" % (" ".join(args[:2]), proc.stderr.strip()[:300]))
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def wait_for(description, check, timeout=420, step=10):
    end = time.time() + timeout
    while time.time() < end:
        if check():
            return
        time.sleep(step)
    raise RuntimeError("timed out waiting for " + description)


def denied(text):
    return "AccessDenied" in text or "not authorized" in text or "UnauthorizedOperation" in text


def policy(filename, swaps):
    text = (POLICY_DIR / filename).read_text()
    for old, new in swaps:
        text = text.replace(old, new)
    return text


def make_role(name, trust, policy_text=None):
    aws("iam", "create-role", "--role-name", name, "--assume-role-policy-document", trust)
    created["roles"].append(name)
    if policy_text:
        aws("iam", "put-role-policy", "--role-name", name, "--policy-name", "under-test", "--policy-document", policy_text)


def assume(role):
    out = aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/%s" % (ACCOUNT, role),
              "--role-session-name", "e2e-test")["Credentials"]
    env = {k: v for k, v in os.environ.items() if k != "AWS_PROFILE"}
    env.update(AWS_ACCESS_KEY_ID=out["AccessKeyId"], AWS_SECRET_ACCESS_KEY=out["SecretAccessKey"],
               AWS_SESSION_TOKEN=out["SessionToken"])
    return env


def setup():
    global ACCOUNT
    ACCOUNT = aws("sts", "get-caller-identity")["Account"]
    ec2_trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
    instance_role = PREFIX + "-instance-role"
    make_role(instance_role, ec2_trust)
    aws("iam", "attach-role-policy", "--role-name", instance_role,
        "--policy-arn", "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
    aws("iam", "create-instance-profile", "--instance-profile-name", instance_role)
    created["profile"] = instance_role
    aws("iam", "add-role-to-instance-profile", "--instance-profile-name", instance_role, "--role-name", instance_role)

    ami = aws("ssm", "get-parameter", "--name",
              "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
    subnet = aws("ec2", "describe-subnets", "--filters", "Name=default-for-az,Values=true")["Subnets"][0]["SubnetId"]

    def launch(name, extra):
        tags = [("Name", name), ("project", PREFIX)] + extra
        tag_arg = "ResourceType=instance,Tags=[" + ",".join("{Key=%s,Value=%s}" % t for t in tags) + "]"
        for _ in range(8):
            ok, text = aws("ec2", "run-instances", "--image-id", ami, "--instance-type", "t3.micro", "--subnet-id", subnet,
                           "--iam-instance-profile", "Name=" + instance_role, "--metadata-options", "HttpTokens=required",
                           "--tag-specifications", tag_arg, "--count", "1", ok_fail=True)
            if ok:
                instance_id = json.loads(text)["Instances"][0]["InstanceId"]
                created["instances"].append(instance_id)
                return instance_id
            time.sleep(8)
        raise RuntimeError("could not launch an instance: " + text[:200])

    tagged = launch(PREFIX + "-tagged", [("AutomationAllowed", "true"), ("Application", "Automated-Deployment-Dev")])
    untagged = launch(PREFIX + "-untagged", [])

    command_doc = {"schemaVersion": "2.2", "description": "test deployment", "mainSteps": [
        {"action": "aws:runShellScript", "name": "deploy", "inputs": {"runCommand": ["echo deployed by the approved document"]}}]}
    runbook = {"schemaVersion": "0.3", "description": "run the approved document on one instance",
               "assumeRole": "{{ AutomationAssumeRole }}",
               "parameters": {"InstanceId": {"type": "String"}, "AutomationAssumeRole": {"type": "String"}},
               "mainSteps": [{"name": "deploy", "action": "aws:runCommand",
                              "inputs": {"DocumentName": "Deploy-Cmd", "InstanceIds": ["{{ InstanceId }}"]}}]}
    for name, kind, body in (("Deploy-Cmd", "Command", command_doc), ("Deploy-E2E-Auto", "Automation", runbook)):
        path = Path("/tmp/%s-%s.json" % (PREFIX, name))
        path.write_text(json.dumps(body))
        aws("ssm", "create-document", "--name", name, "--document-type", kind, "--content", "file://" + str(path))
        created["docs"].append(name)

    # the two roles from Annexure B, with the split hardened policies pointed at what exists
    exec_trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT},
                      "ArnLike": {"aws:SourceArn": "arn:aws:ssm:%s:%s:automation-execution/*" % (REGION, ACCOUNT)}}}]})
    self_trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"}]})
    ssm_trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
    make_role(PREFIX + "-execution-role", exec_trust, policy("ssm-execution-role-policy.json", [
        ("222222222222", ACCOUNT), ("document/Automated-Deployment-Dev", "document/Deploy-Cmd")]))
    make_role(PREFIX + "-dispatcher", self_trust, policy("ssm-dispatcher-role-policy.json", [
        ("222222222222", ACCOUNT), ("document/Automated-Deployment-Dev-Runbook", "document/Deploy-E2E-Auto"),
        ("role/automation_execution_role", "role/" + PREFIX + "-execution-role")]))
    make_role(PREFIX + "-other-role", ssm_trust)   # a role SSM could assume, but not the approved one

    print("waiting for the instances to register with Systems Manager...")

    def registered():
        info = aws("ssm", "describe-instance-information")["InstanceInformationList"]
        online = {i["InstanceId"] for i in info if i["PingStatus"] == "Online"}
        return tagged in online and untagged in online
    wait_for("instances to register", registered)
    time.sleep(20)
    return tagged, untagged


def run_automation(env, instance, role_arn):
    """Start the runbook; return (start result, final status, failure message, step command id)."""
    ok, text = aws("ssm", "start-automation-execution", "--document-name", "Deploy-E2E-Auto", "--parameters",
                   "InstanceId=%s,AutomationAssumeRole=%s" % (instance, role_arn), env=env, ok_fail=True)
    if not ok:
        return ("AccessDenied" if denied(text) else text.strip().splitlines()[-1][:80]), None, "", None
    execution_id = json.loads(text)["AutomationExecutionId"]
    final = {}

    def finished():
        data = aws("ssm", "get-automation-execution", "--automation-execution-id", execution_id)["AutomationExecution"]
        final.update(data)
        return data["AutomationExecutionStatus"] in ("Success", "Failed", "Cancelled", "TimedOut")
    wait_for("the automation to finish", finished, timeout=300, step=8)
    steps = final.get("StepExecutions") or [{}]
    command_ids = (steps[0].get("Outputs") or {}).get("CommandId") or [None]
    return "started", final["AutomationExecutionStatus"], final.get("FailureMessage") or steps[0].get("FailureMessage", ""), command_ids[0]


def run_tests(tagged, untagged):
    dispatcher = assume(PREFIX + "-dispatcher")
    exec_arn = "arn:aws:iam::%s:role/%s-execution-role" % (ACCOUNT, PREFIX)
    other_arn = "arn:aws:iam::%s:role/%s-other-role" % (ACCOUNT, PREFIX)

    start, status, message, command_id = run_automation(dispatcher, tagged, exec_arn)
    results.append(("dispatcher starts the runbook on the tagged instance", start, "started"))
    results.append(("  ...the automation finishes", status, "Success"))
    output = ""
    if command_id:
        ok, text = aws("ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", tagged, ok_fail=True)
        output = json.loads(text).get("StandardOutputContent", "").strip() if ok else ""
    results.append(("  ...and the approved command really ran on the instance",
                    "ran" if output == "deployed by the approved document" else "no output", "ran"))

    start, status, message, _ = run_automation(dispatcher, untagged, exec_arn)
    results.append(("dispatcher starts the runbook on the UNTAGGED instance", start, "started"))
    results.append(("  ...the execution role is stopped by the tag condition", status, "Failed"))
    results.append(("  ...with an access-denied error", "AccessDenied" if denied(message) else message[:70], "AccessDenied"))

    start, _, _, _ = run_automation(dispatcher, tagged, other_arn)
    results.append(("dispatcher passes a different role (iam:PassRole)", start, "AccessDenied"))

    ok, text = aws("ssm", "start-automation-execution", "--document-name", "AWS-RestartEC2Instance", "--parameters",
                   "InstanceId=%s,AutomationAssumeRole=%s" % (tagged, exec_arn), env=dispatcher, ok_fail=True)
    results.append(("dispatcher starts a different runbook", "started" if ok else ("AccessDenied" if denied(text) else text[:60]), "AccessDenied"))

    for label, args in (("dispatcher runs SendCommand directly", ["ssm", "send-command", "--document-name", "AWS-RunShellScript", "--instance-ids", tagged]),
                        ("dispatcher starts an interactive session", ["ssm", "start-session", "--target", tagged]),
                        ("dispatcher tags an instance", ["ec2", "create-tags", "--resources", untagged, "--tags", "Key=AutomationAllowed,Value=true"])):
        ok, text = aws(*args, env=dispatcher, ok_fail=True)
        results.append((label, "OK" if ok else ("AccessDenied" if denied(text) else text[:60]), "AccessDenied"))

    ok, text = aws("sts", "assume-role", "--role-arn", exec_arn, "--role-session-name", "intruder", ok_fail=True)
    results.append(("an ordinary principal assumes the execution role", "assumed" if ok else ("AccessDenied" if denied(text) else text[:60]), "AccessDenied"))


def cleanup():
    print("\ncleaning up...")

    def quiet(*args):
        aws(*args, ok_fail=True)
    if created["instances"]:
        quiet("ec2", "terminate-instances", "--instance-ids", *created["instances"])
    for doc in created["docs"]:
        quiet("ssm", "delete-document", "--name", doc, "--force")
    for role in created["roles"]:
        ok, text = aws("iam", "list-role-policies", "--role-name", role, ok_fail=True)
        for name in (json.loads(text)["PolicyNames"] if ok else []):
            quiet("iam", "delete-role-policy", "--role-name", role, "--policy-name", name)
        ok, text = aws("iam", "list-attached-role-policies", "--role-name", role, ok_fail=True)
        for item in (json.loads(text)["AttachedPolicies"] if ok else []):
            quiet("iam", "detach-role-policy", "--role-name", role, "--policy-arn", item["PolicyArn"])
    if created["profile"]:
        quiet("iam", "remove-role-from-instance-profile", "--instance-profile-name", created["profile"], "--role-name", created["profile"])
        quiet("iam", "delete-instance-profile", "--instance-profile-name", created["profile"])
    for role in created["roles"]:
        quiet("iam", "delete-role", "--role-name", role)
    if created["instances"]:
        try:
            wait_for("instances to terminate", lambda: all(
                i["State"]["Name"] == "terminated" for r in aws("ec2", "describe-instances", "--instance-ids", *created["instances"])["Reservations"]
                for i in r["Instances"]), timeout=300)
        except RuntimeError as err:
            print("WARNING:", err)
    print("cleanup done")


def main():
    try:
        tagged, untagged = setup()
        run_tests(tagged, untagged)
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
