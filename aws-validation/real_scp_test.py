#!/usr/bin/env python3
"""Attach the three SCPs in a real AWS Organization and test them with real API calls.

Needs: an AWS Organization (all features, SCPs enabled) with at least one member account that
has the OrganizationAccountAccessRole, and credentials for the management account.
Set MEMBER_ACCOUNT_ID, or let the script use the member account called "scp-test-member".

It creates a throwaway OU, moves the member account into it, attaches each SCP in turn,
probes from the member account, and then undoes everything (the SCPs, the OU and the test
role are deleted and the member account goes back to the root).

ECR is the regional service used for the probes, because a brand-new account has not yet
activated most services. IAM is the global service.

Usage: AWS_PROFILE=<management account profile> python3 aws-validation/real_scp_test.py
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCP_DIR = HERE.parent / "required-scp"
REGION = "eu-west-1"
DENIED = "explicit deny in a service control policy"

created = {"policies": [], "ou": None, "moved_from": None, "role": None}
results = []


def aws(*args, env=None, ok_fail=False, region=REGION):
    cmd = ["aws", *args, "--region", region, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if ok_fail:
        return proc.returncode == 0, (proc.stdout if proc.returncode == 0 else proc.stderr)
    if proc.returncode:
        raise RuntimeError("aws %s failed: %s" % (" ".join(args[:2]), proc.stderr.strip()[:300]))
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def credentials_env(creds):
    env = {k: v for k, v in os.environ.items() if k != "AWS_PROFILE"}
    env.update(AWS_ACCESS_KEY_ID=creds["AccessKeyId"], AWS_SECRET_ACCESS_KEY=creds["SecretAccessKey"],
               AWS_SESSION_TOKEN=creds["SessionToken"])
    return env


def assume(account, role_name, session):
    creds = aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/%s" % (account, role_name),
                "--role-session-name", session, "--duration-seconds", "3600")["Credentials"]
    return credentials_env(creds)


def probe(env, service_args, region):
    """Return 'allowed', 'DENIED by SCP' or the first line of another error."""
    ok, text = aws(*service_args, env=env, ok_fail=True, region=region)
    if ok:
        return "allowed"
    if DENIED in text:
        return "DENIED by SCP"
    lines = [line for line in text.splitlines() if line.strip()]
    return "other: " + (lines[0][:80] if lines else "no output")


def ecr(env, region):
    return probe(env, ["ecr", "describe-repositories"], region)


def iam(env):
    return probe(env, ["iam", "list-roles"], "us-east-1")


def wait_until(canary, want, timeout=240):
    """SCPs take a little while to apply; poll a canary call until it shows the new state."""
    end = time.time() + timeout
    while time.time() < end:
        if canary() == want:
            return
        time.sleep(10)
    raise RuntimeError("the SCP did not take effect within %ds" % timeout)


def check(label, got, want):
    results.append((label, got, want))


def create_scp(name, filename):
    policy = aws("organizations", "create-policy", "--name", name, "--type", "SERVICE_CONTROL_POLICY",
                 "--description", "Temporary test copy of " + filename,
                 "--content", "file://" + str(SCP_DIR / filename))["Policy"]["PolicySummary"]["Id"]
    created["policies"].append(policy)
    return policy


def attach_only(policy_id, ou, previous):
    if previous:
        aws("organizations", "detach-policy", "--policy-id", previous, "--target-id", ou)
    if policy_id:
        aws("organizations", "attach-policy", "--policy-id", policy_id, "--target-id", ou)


def find_member():
    member = os.environ.get("MEMBER_ACCOUNT_ID")
    if member:
        return member
    accounts = aws("organizations", "list-accounts")["Accounts"]
    for account in accounts:
        if account["Name"] == "scp-test-member":
            return account["Id"]
    raise RuntimeError("no member account found; set MEMBER_ACCOUNT_ID")


def run_tests():
    root = aws("organizations", "list-roots")["Roots"][0]["Id"]
    member = find_member()
    print("member account", member)

    ou = aws("organizations", "create-organizational-unit", "--parent-id", root,
             "--name", "scp-test-ou")["OrganizationalUnit"]["Id"]
    created["ou"] = ou
    aws("organizations", "move-account", "--account-id", member, "--source-parent-id", root,
        "--destination-parent-id", ou)
    created["moved_from"] = root

    main_id = create_scp("TestRestrictToEuWest1", "scp-restrict-to-eu-west-1.json")
    strict_id = create_scp("TestStrictAllServices", "scp-strict-all-services.json")
    breakglass_id = create_scp("TestBreakGlass", "scp-restrict-to-eu-west-1-with-breakglass.json")

    admin_env = assume(member, "OrganizationAccountAccessRole", "scp-test")   # exempt in the break-glass variant

    print("baseline, no SCP")
    check("no SCP: ECR eu-west-1", ecr(admin_env, "eu-west-1"), "allowed")
    check("no SCP: ECR us-east-1", ecr(admin_env, "us-east-1"), "allowed")
    check("no SCP: IAM", iam(admin_env), "allowed")

    print("main SCP")
    attach_only(main_id, ou, None)
    wait_until(lambda: ecr(admin_env, "us-east-1"), "DENIED by SCP")
    check("main SCP: ECR eu-west-1", ecr(admin_env, "eu-west-1"), "allowed")
    for r in ("us-east-1", "ap-south-1", "eu-central-1"):
        check("main SCP: ECR " + r, ecr(admin_env, r), "DENIED by SCP")
    check("main SCP: IAM (global, exempt)", iam(admin_env), "allowed")

    print("strict SCP")
    attach_only(strict_id, ou, main_id)
    wait_until(lambda: iam(admin_env), "DENIED by SCP")
    check("strict SCP: ECR eu-west-1", ecr(admin_env, "eu-west-1"), "allowed")
    for r in ("us-east-1", "ap-south-1"):
        check("strict SCP: ECR " + r, ecr(admin_env, r), "DENIED by SCP")
    check("strict SCP: IAM (global, not exempt)", iam(admin_env), "DENIED by SCP")

    print("break-glass variant")
    attach_only(breakglass_id, ou, strict_id)
    wait_until(lambda: iam(admin_env), "allowed")
    # a second role in the member account that is NOT on the exemption list
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % member}, "Action": "sts:AssumeRole"}]})
    aws("iam", "create-role", "--role-name", "ScpNotExempt", "--assume-role-policy-document", trust, env=admin_env)
    created["role"] = ("ScpNotExempt", admin_env)
    aws("iam", "attach-role-policy", "--role-name", "ScpNotExempt", "--policy-arn",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly", env=admin_env)
    time.sleep(15)
    other_env = credentials_env(aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/ScpNotExempt" % member,
                                    "--role-session-name", "not-exempt", env=admin_env)["Credentials"])
    check("break-glass: exempt role, ECR us-east-1", ecr(admin_env, "us-east-1"), "allowed")
    check("break-glass: other role, ECR eu-west-1", ecr(other_env, "eu-west-1"), "allowed")
    check("break-glass: other role, ECR us-east-1", ecr(other_env, "us-east-1"), "DENIED by SCP")


def cleanup():
    print("\ncleaning up...")

    def quiet(*args, env=None):
        aws(*args, ok_fail=True, env=env)
    if created["role"]:
        name, env = created["role"]
        quiet("iam", "detach-role-policy", "--role-name", name,
              "--policy-arn", "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly", env=env)
        quiet("iam", "delete-role", "--role-name", name, env=env)
    if created["ou"]:
        for policy_id in created["policies"]:
            quiet("organizations", "detach-policy", "--policy-id", policy_id, "--target-id", created["ou"])
        member = find_member()
        quiet("organizations", "move-account", "--account-id", member,
              "--source-parent-id", created["ou"], "--destination-parent-id", created["moved_from"])
        quiet("organizations", "delete-organizational-unit", "--organizational-unit-id", created["ou"])
    for policy_id in created["policies"]:
        quiet("organizations", "delete-policy", "--policy-id", policy_id)
    print("cleanup done")


def main():
    try:
        run_tests()
    finally:
        cleanup()
    print("\n%-48s %-16s %s" % ("check", "result", "expected"))
    bad = 0
    for label, got, want in results:
        bad += got != want
        print("[%s] %-43s %-16s %s" % ("ok  " if got == want else "FAIL", label, got, want))
    print("\n%s" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
