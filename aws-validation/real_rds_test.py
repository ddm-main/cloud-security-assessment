#!/usr/bin/env python3
"""Test the Annexure C RDS policies (Admin, CRUB, ReadOnly) against a real RDS instance.

It creates one small private PostgreSQL instance, a snapshot, a log group, an SNS topic and
three roles carrying the three policies. It then makes real control-plane calls as each role
and compares the result with what the risk review says. Everything is deleted at the end.
Cost: a few cents, but the database takes around 10 minutes to become available.

It does not log in to the database: real_rds_login_test.py does that.

Usage: AWS_PROFILE=<admin profile> SHARE_WITH_ACCOUNT=<another 12-digit account ID> \
       python3 aws-validation/real_rds_test.py
"""
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

REGION = "eu-west-1"
HERE = Path(__file__).resolve().parent
PREFIX = "rds-policy-test"
DB = PREFIX + "-db"
SNAPSHOT = PREFIX + "-snap"
LOG_GROUP = "/test/" + PREFIX
TOPIC = PREFIX + "-topic"
# another AWS account ID. The snapshot is shared with it for a moment, then unshared.
SHARE_WITH = os.environ.get("SHARE_WITH_ACCOUNT", "")

created = {"db": False, "snapshot": False, "log_group": False, "topic_arn": None, "roles": []}
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


def outcome(ok, text):
    """OK, AccessDenied, 'authorised' (AWS got past IAM and rejected the request for another reason), or the code."""
    if ok:
        return "OK"
    if "AccessDenied" in text or "not authorized" in text:
        return "AccessDenied"
    start = text.find("(")
    code = text[start + 1:text.find(")", start)] if start != -1 else text.strip()[:60]
    return "authorised" if code in ("InvalidParameterCombination", "InvalidDBInstanceState") else code


def wait_for(description, check, timeout, step=20):
    end = time.time() + timeout
    while time.time() < end:
        if check():
            return
        time.sleep(step)
    raise RuntimeError("timed out waiting for " + description)


def db_status():
    ok, text = aws("rds", "describe-db-instances", "--db-instance-identifier", DB, ok_fail=True)
    return json.loads(text)["DBInstances"][0]["DBInstanceStatus"] if ok else "gone"


def setup():
    global ACCOUNT
    if not (SHARE_WITH.isdigit() and len(SHARE_WITH) == 12):
        sys.exit("set SHARE_WITH_ACCOUNT to another 12-digit AWS account ID (used for the snapshot sharing check)")
    ACCOUNT = aws("sts", "get-caller-identity")["Account"]
    print("account", ACCOUNT)

    # the master password is random and never shown or stored
    aws("rds", "create-db-instance", "--db-instance-identifier", DB, "--engine", "postgres",
        "--db-instance-class", "db.t4g.micro", "--allocated-storage", "20",
        "--master-username", "dbadmin", "--master-user-password", secrets.token_urlsafe(18),
        "--no-publicly-accessible", "--enable-iam-database-authentication", "--deletion-protection",
        "--backup-retention-period", "1", "--storage-encrypted")
    created["db"] = True

    aws("logs", "create-log-group", "--log-group-name", LOG_GROUP)
    created["log_group"] = True
    now = int(time.time() * 1000)
    aws("logs", "create-log-stream", "--log-group-name", LOG_GROUP, "--log-stream-name", "s")
    aws("logs", "put-log-events", "--log-group-name", LOG_GROUP, "--log-stream-name", "s",
        "--log-events", json.dumps([{"timestamp": now, "message": "an application log line"}]))
    created["topic_arn"] = aws("sns", "create-topic", "--name", TOPIC)["TopicArn"]

    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"}]})
    for label in ("admin", "crub", "readonly", "recommended"):
        name = "%s-%s" % (PREFIX, label)
        aws("iam", "create-role", "--role-name", name, "--assume-role-policy-document", trust)
        created["roles"].append(name)
        if label == "recommended":
            # the recommended read-only permission set, pointed at this account and database
            text = (HERE.parent / "risk-review" / "rds-recommended-readonly-permission-set.json").read_text()
            text = text.replace("<ACCOUNT_ID>", ACCOUNT).replace("<DbiResourceId>", "db-PLACEHOLDER")
        else:
            text = (HERE / ("rds-%s.json" % label)).read_text()
        aws("iam", "put-role-policy", "--role-name", name, "--policy-name", "under-test", "--policy-document", text)

    print("waiting for the database to become available (about 10 minutes)...")
    wait_for("database", lambda: db_status() == "available", timeout=1500)

    aws("rds", "create-db-snapshot", "--db-instance-identifier", DB, "--db-snapshot-identifier", SNAPSHOT)
    created["snapshot"] = True
    print("waiting for the snapshot...")

    def snap_ready():
        snaps = aws("rds", "describe-db-snapshots", "--db-snapshot-identifier", SNAPSHOT)["DBSnapshots"]
        return snaps[0]["Status"] == "available"
    wait_for("snapshot", snap_ready, timeout=900)
    time.sleep(15)   # let the roles propagate


def assume(role):
    out = aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/%s" % (ACCOUNT, role),
              "--role-session-name", "policy-test")["Credentials"]
    env = {k: v for k, v in os.environ.items() if k != "AWS_PROFILE"}
    env.update(AWS_ACCESS_KEY_ID=out["AccessKeyId"], AWS_SECRET_ACCESS_KEY=out["SecretAccessKey"],
               AWS_SESSION_TOKEN=out["SessionToken"])
    return env


def run_role(label, env, expect):
    cases = []

    ok, text = aws("rds", "describe-db-instances", "--db-instance-identifier", DB, env=env, ok_fail=True)
    cases.append(("DescribeDBInstances", outcome(ok, text)))

    # a master password reset gives superuser in the database, whatever grants the DB roles have
    ok, text = aws("rds", "modify-db-instance", "--db-instance-identifier", DB, "--apply-immediately",
                   "--master-user-password", secrets.token_urlsafe(18), env=env, ok_fail=True)
    got = outcome(ok, text)
    # an earlier reset can leave the instance busy; a state error still means IAM allowed the call
    cases.append(("ModifyDBInstance: reset the master password", "OK" if got == "authorised" else got))

    # deletion protection is on, so a role that is allowed to delete gets an error that is NOT AccessDenied
    ok, text = aws("rds", "delete-db-instance", "--db-instance-identifier", DB, "--skip-final-snapshot",
                   env=env, ok_fail=True)
    cases.append(("DeleteDBInstance (blocked only by deletion protection)", outcome(ok, text)))

    ok, text = aws("rds", "modify-db-snapshot-attribute", "--db-snapshot-identifier", SNAPSHOT,
                   "--attribute-name", "restore", "--values-to-add", SHARE_WITH, env=env, ok_fail=True)
    cases.append(("ModifyDBSnapshotAttribute: share the snapshot with another account", outcome(ok, text)))
    if ok:   # undo straight away
        aws("rds", "modify-db-snapshot-attribute", "--db-snapshot-identifier", SNAPSHOT,
            "--attribute-name", "restore", "--values-to-remove", SHARE_WITH, ok_fail=True)

    ok, text = aws("logs", "get-log-events", "--log-group-name", LOG_GROUP, "--log-stream-name", "s",
                   env=env, ok_fail=True)
    cases.append(("logs GetLogEvents on an unrelated log group", outcome(ok, text)))

    ok, text = aws("sns", "publish", "--topic-arn", created["topic_arn"], "--message", "test", env=env, ok_fail=True)
    cases.append(("sns Publish to an unrelated topic", outcome(ok, text)))

    ok, text = aws("cloudwatch", "delete-alarms", "--alarm-names", PREFIX + "-no-such-alarm", env=env, ok_fail=True)
    cases.append(("cloudwatch DeleteAlarms", outcome(ok, text)))

    for name, got in cases:
        results.append(("%-8s %s" % (label, name), got, expect[name]))


def cleanup():
    print("\ncleaning up...")

    def quiet(*args):
        aws(*args, ok_fail=True)
    if created["db"]:
        for _ in range(30):   # the instance may still be busy with a password reset
            ok, _text = aws("rds", "modify-db-instance", "--db-instance-identifier", DB,
                            "--no-deletion-protection", "--apply-immediately", ok_fail=True)
            if ok:
                break
            time.sleep(20)
        time.sleep(5)
        quiet("rds", "delete-db-instance", "--db-instance-identifier", DB, "--skip-final-snapshot", "--delete-automated-backups")
    if created["snapshot"]:
        quiet("rds", "modify-db-snapshot-attribute", "--db-snapshot-identifier", SNAPSHOT,
              "--attribute-name", "restore", "--values-to-remove", SHARE_WITH)
        quiet("rds", "delete-db-snapshot", "--db-snapshot-identifier", SNAPSHOT)
    if created["log_group"]:
        quiet("logs", "delete-log-group", "--log-group-name", LOG_GROUP)
    if created["topic_arn"]:
        quiet("sns", "delete-topic", "--topic-arn", created["topic_arn"])
    for role in created["roles"]:
        quiet("iam", "delete-role-policy", "--role-name", role, "--policy-name", "under-test")
        quiet("iam", "delete-role", "--role-name", role)
    if created["db"]:
        try:
            wait_for("database to be deleted", lambda: db_status() == "gone", timeout=1200)
        except RuntimeError as err:
            print("WARNING:", err, "- check the RDS console for", DB)
    print("cleanup done")


EXPECT = {
    "recommended": {
        "DescribeDBInstances": "OK",
        "ModifyDBInstance: reset the master password": "AccessDenied",
        "DeleteDBInstance (blocked only by deletion protection)": "AccessDenied",
        "ModifyDBSnapshotAttribute: share the snapshot with another account": "AccessDenied",
        "logs GetLogEvents on an unrelated log group": "AccessDenied",
        "sns Publish to an unrelated topic": "AccessDenied",
        "cloudwatch DeleteAlarms": "AccessDenied",
    },
    "admin": {
        "DescribeDBInstances": "OK",
        "ModifyDBInstance: reset the master password": "OK",
        "DeleteDBInstance (blocked only by deletion protection)": "authorised",
        "ModifyDBSnapshotAttribute: share the snapshot with another account": "OK",
        "logs GetLogEvents on an unrelated log group": "OK",
        "sns Publish to an unrelated topic": "OK",
        "cloudwatch DeleteAlarms": "OK",
    },
    "crub": {
        "DescribeDBInstances": "OK",
        "ModifyDBInstance: reset the master password": "OK",
        "DeleteDBInstance (blocked only by deletion protection)": "authorised",
        "ModifyDBSnapshotAttribute: share the snapshot with another account": "OK",
        "logs GetLogEvents on an unrelated log group": "AccessDenied",
        "sns Publish to an unrelated topic": "AccessDenied",
        "cloudwatch DeleteAlarms": "AccessDenied",
    },
    "readonly": {
        "DescribeDBInstances": "OK",
        "ModifyDBInstance: reset the master password": "AccessDenied",
        "DeleteDBInstance (blocked only by deletion protection)": "AccessDenied",
        "ModifyDBSnapshotAttribute: share the snapshot with another account": "AccessDenied",
        "logs GetLogEvents on an unrelated log group": "AccessDenied",
        "sns Publish to an unrelated topic": "AccessDenied",
        "cloudwatch DeleteAlarms": "AccessDenied",
    },
}


def main():
    try:
        setup()
        for label in ("readonly", "recommended", "crub", "admin"):
            run_role(label, assume("%s-%s" % (PREFIX, label)), EXPECT[label])
    finally:
        cleanup()

    print("\n%-90s %-14s %s" % ("check", "result", "expected"))
    bad = 0
    for name, got, want in results:
        bad += got != want
        print("[%s] %-85s %-14s %s" % ("ok  " if got == want else "FAIL", name, got, want))
    print("\n%s" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
