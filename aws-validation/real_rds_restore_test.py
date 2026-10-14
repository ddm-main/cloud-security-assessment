#!/usr/bin/env python3
"""Can each Annexure C role restore a database from a snapshot?

Restoring builds a second database, which takes 10 minutes and costs money, so this test asks
for a snapshot that does not exist. AWS checks the caller's permissions before it looks for the
snapshot: a role that is allowed gets DBSnapshotNotFound, a role that is not gets AccessDenied.
Nothing is created except four temporary roles, which are deleted again.

Usage: AWS_PROFILE=<admin profile> python3 aws-validation/real_rds_restore_test.py
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REGION = "eu-west-1"
HERE = Path(__file__).resolve().parent
PREFIX = "rds-restore-test"
created = []
results = []


def aws(*args, env=None, ok_fail=False):
    cmd = ["aws", *args, "--region", REGION, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if ok_fail:
        return proc.returncode == 0, (proc.stdout if proc.returncode == 0 else proc.stderr)
    if proc.returncode:
        raise RuntimeError("aws %s failed: %s" % (" ".join(args[:2]), proc.stderr.strip()[:300]))
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def main():
    account = aws("sts", "get-caller-identity")["Account"]
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % account}, "Action": "sts:AssumeRole"}]})
    recommended = (HERE.parent / "risk-review" / "rds-recommended-readonly-permission-set.json").read_text()
    recommended = recommended.replace("<ACCOUNT_ID>", account).replace("<DbiResourceId>", "db-PLACEHOLDER")
    policies = {"admin": (HERE / "rds-admin.json").read_text(), "crub": (HERE / "rds-crub.json").read_text(),
                "readonly": (HERE / "rds-readonly.json").read_text(), "recommended": recommended}
    expect = {"admin": "authorised", "crub": "authorised", "readonly": "AccessDenied", "recommended": "AccessDenied"}
    try:
        for label, policy in policies.items():
            name = "%s-%s" % (PREFIX, label)
            aws("iam", "create-role", "--role-name", name, "--assume-role-policy-document", trust)
            created.append(name)
            aws("iam", "put-role-policy", "--role-name", name, "--policy-name", "under-test", "--policy-document", policy)
        time.sleep(15)
        for label in policies:
            creds = aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/%s-%s" % (account, PREFIX, label),
                        "--role-session-name", "restore-test")["Credentials"]
            env = {k: v for k, v in os.environ.items() if k != "AWS_PROFILE"}
            env.update(AWS_ACCESS_KEY_ID=creds["AccessKeyId"], AWS_SECRET_ACCESS_KEY=creds["SecretAccessKey"],
                       AWS_SESSION_TOKEN=creds["SessionToken"])
            ok, text = aws("rds", "restore-db-instance-from-db-snapshot", "--db-instance-identifier", PREFIX + "-new",
                           "--db-snapshot-identifier", PREFIX + "-no-such-snapshot", env=env, ok_fail=True)
            if ok:
                got = "restored (unexpected)"
            elif "AccessDenied" in text or "not authorized" in text:
                got = "AccessDenied"
            elif "DBSnapshotNotFound" in text:
                got = "authorised"
            else:
                got = "other: " + text.strip().splitlines()[-1][:80]
            results.append(("%-11s RestoreDBInstanceFromDBSnapshot" % label, got, expect[label]))
    finally:
        for name in created:
            aws("iam", "delete-role-policy", "--role-name", name, "--policy-name", "under-test", ok_fail=True)
            aws("iam", "delete-role", "--role-name", name, ok_fail=True)

    print("%-48s %-14s %s" % ("check", "result", "expected"))
    bad = 0
    for label, got, want in results:
        bad += got != want
        print("[%s] %-43s %-14s %s" % ("ok  " if got == want else "FAIL", label, got, want))
    print("\n%s" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
