#!/usr/bin/env python3
"""Test the session claims in the RDS review with real role sessions.

  * A condition on aws:MultiFactorAuthPresent denies a session that was started without MFA.
    The review says enforcing MFA that way would lock out SAML-federated users, because their
    sessions do not carry the key. Here the session comes from assume-role without MFA, which is
    the same situation: the key is absent.
  * Revoking sessions with an aws:TokenIssueTime deny kills sessions issued before it and leaves
    new ones working (the review's answer to "the leaver keeps a live session").
  * What happens to a live session when its permissions are removed, and when its role is deleted.

ECR (read-only list call) is the probe. Needs only IAM and STS. Everything created is deleted.

Usage: AWS_PROFILE=<admin profile> python3 aws-validation/real_session_test.py
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

REGION = "eu-west-1"
PREFIX = "session-test"
created = []
results = []
ACCOUNT = None
ALLOW_ECR = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "ecr:DescribeRepositories", "Resource": "*"}]})


def aws(*args, env=None, ok_fail=False):
    cmd = ["aws", *args, "--region", REGION, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if ok_fail:
        return proc.returncode == 0, (proc.stdout if proc.returncode == 0 else proc.stderr)
    if proc.returncode:
        raise RuntimeError("aws %s failed: %s" % (" ".join(args[:2]), proc.stderr.strip()[:300]))
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def make_role(label, policy):
    name = "%s-%s" % (PREFIX, label)
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"}]})
    aws("iam", "create-role", "--role-name", name, "--assume-role-policy-document", trust)
    created.append(name)
    if policy:
        aws("iam", "put-role-policy", "--role-name", name, "--policy-name", "allow", "--policy-document", policy)
    return name


def session(role):
    c = aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/%s" % (ACCOUNT, role),
            "--role-session-name", "session-test")["Credentials"]
    env = {k: v for k, v in os.environ.items() if k != "AWS_PROFILE"}
    env.update(AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])
    return env


def probe(env):
    ok, text = aws("ecr", "describe-repositories", env=env, ok_fail=True)
    if ok:
        return "allowed"
    if "AccessDenied" in text or "not authorized" in text:
        return "denied"
    if "InvalidClientTokenId" in text or "ExpiredToken" in text or "UnrecognizedClient" in text:
        return "session invalid"
    return "other: " + text.strip().splitlines()[-1][:80]


def wait_for(env, want, seconds=90):
    end = time.time() + seconds
    got = probe(env)
    while got != want and time.time() < end:
        time.sleep(4)
        got = probe(env)
    return got


def check(label, got, want):
    results.append((label, got, want))


def run():
    global ACCOUNT
    ACCOUNT = aws("sts", "get-caller-identity")["Account"]

    # 1. MFA condition
    mfa_policy = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "ecr:DescribeRepositories", "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]})
    with_mfa = make_role("needs-mfa", mfa_policy)
    plain = make_role("plain", ALLOW_ECR)
    time.sleep(12)
    check("role session without MFA, policy requires MFA", wait_for(session(with_mfa), "denied", 30), "denied")
    check("role session without MFA, same policy without the condition", wait_for(session(plain), "allowed", 60), "allowed")

    # 2. revoking sessions with aws:TokenIssueTime
    revoke = make_role("revoke", ALLOW_ECR)
    time.sleep(12)
    old = session(revoke)
    check("revoke: session works before the revoke policy", wait_for(old, "allowed", 60), "allowed")
    time.sleep(3)
    cutoff = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    time.sleep(3)
    aws("iam", "put-role-policy", "--role-name", revoke, "--policy-name", "revoke-older-sessions", "--policy-document",
        json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}}}]}))
    check("revoke: the old session after the revoke policy", wait_for(old, "denied", 90), "denied")
    new = session(revoke)
    check("revoke: a session started after the revoke policy", wait_for(new, "allowed", 60), "allowed")

    # 3. permissions removed while a session is live
    stripped = make_role("strip", ALLOW_ECR)
    time.sleep(12)
    live = session(stripped)
    check("strip: session works before the policy is removed", wait_for(live, "allowed", 60), "allowed")
    aws("iam", "delete-role-policy", "--role-name", stripped, "--policy-name", "allow")
    check("strip: the live session after its policy is deleted", wait_for(live, "denied", 90), "denied")

    # 4. role deleted while a session is live
    doomed = make_role("delete", ALLOW_ECR)
    time.sleep(12)
    live = session(doomed)
    check("delete: session works before the role is deleted", wait_for(live, "allowed", 60), "allowed")
    aws("iam", "delete-role-policy", "--role-name", doomed, "--policy-name", "allow")
    aws("iam", "delete-role", "--role-name", doomed)
    created.remove(doomed)
    time.sleep(20)
    check("delete: the live session after its role is deleted", probe(live), "session invalid")


def cleanup():
    for name in created:
        ok, text = aws("iam", "list-role-policies", "--role-name", name, ok_fail=True)
        for p in (json.loads(text)["PolicyNames"] if ok else []):
            aws("iam", "delete-role-policy", "--role-name", name, "--policy-name", p, ok_fail=True)
        aws("iam", "delete-role", "--role-name", name, ok_fail=True)


def main():
    try:
        run()
    finally:
        cleanup()
    print("%-70s %-16s %s" % ("check", "result", "expected"))
    bad = 0
    for label, got, want in results:
        bad += got != want
        print("[%s] %-65s %-16s %s" % ("ok  " if got == want else "FAIL", label, got, want))
    print("\n%s" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
