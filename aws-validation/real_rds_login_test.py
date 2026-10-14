#!/usr/bin/env python3
"""Log in to a real RDS database with IAM authentication and test who can do what.

The control-plane test (real_rds_test.py) cannot show whether a role can log in to the database
and run SQL. This one does. It creates a small PostgreSQL instance that is reachable only from
your own public IP address (a security group with a single /32 rule), creates three database users
inside it with different grants, and then logs in through IAM tokens issued to different roles.

What it checks:
  * rds-db:connect lets a role log in as exactly one database user, and nobody else
  * what that database user can do is decided by the database grants, not by IAM
  * the three Annexure C policies grant no way to log in at all
  * the "CRUB" role can reset the master password and then take over the database
  * ModifyDBParameterGroup (turning off auditing) per role

Everything is deleted at the end: database, security group, parameter group and roles.
Needs the psql client (brew install libpq). The run takes about 20 minutes, mostly the database build.

Usage: AWS_PROFILE=<admin profile> python3 aws-validation/real_rds_login_test.py
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REGION = "eu-west-1"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PREFIX = "rds-login-test"
DB = PREFIX + "-db"
SG_NAME = PREFIX + "-sg"
PG_NAME = PREFIX + "-pg"
HOST_DB = "postgres"

created = {"db": False, "sg": None, "pg": False, "roles": []}
results = []
state = {}


def aws(*args, env=None, ok_fail=False):
    cmd = ["aws", *args, "--region", REGION, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if ok_fail:
        return proc.returncode == 0, (proc.stdout if proc.returncode == 0 else proc.stderr)
    if proc.returncode:
        raise RuntimeError("aws %s failed: %s" % (" ".join(args[:2]), proc.stderr.strip()[:300]))
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def find_psql():
    for candidate in (shutil.which("psql"), "/opt/homebrew/opt/libpq/bin/psql", "/usr/local/opt/libpq/bin/psql"):
        if candidate and Path(candidate).exists():
            return candidate
    sys.exit("psql not found: brew install libpq")


def wait_for(description, check, timeout, step=15):
    end = time.time() + timeout
    while time.time() < end:
        if check():
            return
        time.sleep(step)
    raise RuntimeError("timed out waiting for " + description)


def db_info():
    ok, text = aws("rds", "describe-db-instances", "--db-instance-identifier", DB, ok_fail=True)
    return json.loads(text)["DBInstances"][0] if ok else None


def db_status():
    info = db_info()
    return info["DBInstanceStatus"] if info else "gone"


def classify(proc):
    if proc.returncode == 0:
        return "ok"
    err = proc.stderr.lower()
    if "permission denied" in err or "must be owner" in err:
        return "permission denied"
    if "authentication failed" in err or "no pg_hba.conf entry" in err:
        return "login refused"
    return "error: " + (proc.stderr.strip().splitlines() or ["?"])[-1][:70]


def sql(user, password, statement):
    cmd = [state["psql"], "host=%s port=5432 dbname=%s user=%s sslmode=require connect_timeout=15" % (
        state["host"], HOST_DB, user), "-v", "ON_ERROR_STOP=1", "-tAc", statement]
    env = dict(os.environ, PGPASSWORD=password)
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)


def token_for(role_env, db_user):
    """An IAM auth token is signed locally; whether it works is decided when the database checks it."""
    cmd = ["aws", "rds", "generate-db-auth-token", "--hostname", state["host"], "--port", "5432",
           "--username", db_user, "--region", REGION]
    return subprocess.run(cmd, capture_output=True, text=True, env=role_env).stdout.strip()


def as_role(label, role_env, db_user, statement):
    return classify(sql(db_user, token_for(role_env, db_user), statement))


def assume(role):
    out = aws("sts", "assume-role", "--role-arn", "arn:aws:iam::%s:role/%s" % (state["account"], role),
              "--role-session-name", "login-test")["Credentials"]
    env = {k: v for k, v in os.environ.items() if k != "AWS_PROFILE"}
    env.update(AWS_ACCESS_KEY_ID=out["AccessKeyId"], AWS_SECRET_ACCESS_KEY=out["SecretAccessKey"],
               AWS_SESSION_TOKEN=out["SessionToken"])
    return env


def my_ip():
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=15) as response:
        return response.read().decode().strip()


def add_role(name, policy_text):
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % state["account"]}, "Action": "sts:AssumeRole"}]})
    aws("iam", "create-role", "--role-name", name, "--assume-role-policy-document", trust)
    created["roles"].append(name)
    aws("iam", "put-role-policy", "--role-name", name, "--policy-name", "under-test", "--policy-document", policy_text)


def connect_policy(resource_id, db_user):
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "rds-db:connect",
        "Resource": "arn:aws:rds-db:%s:%s:dbuser:%s/%s" % (REGION, state["account"], resource_id, db_user)}]})


def setup():
    state["psql"] = find_psql()
    state["account"] = aws("sts", "get-caller-identity")["Account"]
    state["master_password"] = secrets.token_urlsafe(18)
    ip = my_ip()
    print("account", state["account"], "- the database will accept connections only from this machine's IP")

    vpc = aws("ec2", "describe-vpcs", "--filters", "Name=isDefault,Values=true")["Vpcs"][0]["VpcId"]
    sg = aws("ec2", "create-security-group", "--group-name", SG_NAME, "--description", "rds login test, one IP only",
             "--vpc-id", vpc)["GroupId"]
    created["sg"] = sg
    aws("ec2", "authorize-security-group-ingress", "--group-id", sg, "--protocol", "tcp", "--port", "5432",
        "--cidr", ip + "/32")

    version = aws("rds", "describe-db-engine-versions", "--engine", "postgres", "--default-only")["DBEngineVersions"][0]
    aws("rds", "create-db-parameter-group", "--db-parameter-group-name", PG_NAME,
        "--db-parameter-group-family", version["DBParameterGroupFamily"], "--description", "login test")
    created["pg"] = True

    aws("rds", "create-db-instance", "--db-instance-identifier", DB, "--engine", "postgres",
        "--engine-version", version["EngineVersion"], "--db-instance-class", "db.t4g.micro",
        "--allocated-storage", "20", "--master-username", "dbadmin", "--master-user-password", state["master_password"],
        "--publicly-accessible", "--vpc-security-group-ids", sg, "--enable-iam-database-authentication",
        "--backup-retention-period", "0", "--storage-encrypted", "--no-deletion-protection")
    created["db"] = True
    print("waiting for the database (about 10 minutes)...")
    wait_for("database", lambda: db_status() == "available", timeout=1500)
    info = db_info()
    state["host"] = info["Endpoint"]["Address"]
    state["resource_id"] = info["DbiResourceId"]

    # three database users with different grants, created inside the database
    admin_sql = """
        CREATE TABLE accounts (id int, owner text);
        INSERT INTO accounts VALUES (1, 'alice');
        CREATE USER app_readonly; GRANT rds_iam TO app_readonly; GRANT SELECT ON accounts TO app_readonly;
        CREATE USER app_crud;     GRANT rds_iam TO app_crud;     GRANT SELECT, INSERT, UPDATE, DELETE ON accounts TO app_crud;
        CREATE USER app_admin;    GRANT rds_iam TO app_admin;    GRANT ALL ON SCHEMA public TO app_admin;
    """
    for attempt in range(10):   # the endpoint can need a moment to accept connections
        proc = sql("dbadmin", state["master_password"], admin_sql)
        if proc.returncode == 0:
            break
        time.sleep(15)
    else:
        raise RuntimeError("could not set up database users: " + proc.stderr[:200])

    rid = state["resource_id"]
    recommended = (ROOT / "risk-review" / "rds-recommended-readonly-permission-set.json").read_text()
    recommended = recommended.replace("<ACCOUNT_ID>", state["account"]).replace("<DbiResourceId>", rid)
    add_role(PREFIX + "-readonly", recommended)
    add_role(PREFIX + "-crud", connect_policy(rid, "app_crud"))
    add_role(PREFIX + "-admin", connect_policy(rid, "app_admin"))
    for name in ("readonly", "crub", "admin"):
        add_role("%s-annexure-%s" % (PREFIX, name), (HERE / ("rds-%s.json" % name)).read_text())
    time.sleep(15)


def check(label, got, want):
    results.append((label, got, want))


def run_tests():
    readonly = assume(PREFIX + "-readonly")
    crud = assume(PREFIX + "-crud")
    admin = assume(PREFIX + "-admin")

    print("logging in as each database user")
    check("readonly user: SELECT", as_role("r", readonly, "app_readonly", "SELECT count(*) FROM accounts"), "ok")
    check("readonly user: INSERT", as_role("r", readonly, "app_readonly", "INSERT INTO accounts VALUES (2, 'bob')"), "permission denied")
    check("readonly user: CREATE TABLE", as_role("r", readonly, "app_readonly", "CREATE TABLE x (a int)"), "permission denied")
    check("readonly user: DROP TABLE", as_role("r", readonly, "app_readonly", "DROP TABLE accounts"), "permission denied")

    check("crud user: SELECT", as_role("c", crud, "app_crud", "SELECT count(*) FROM accounts"), "ok")
    check("crud user: INSERT", as_role("c", crud, "app_crud", "INSERT INTO accounts VALUES (3, 'carol')"), "ok")
    check("crud user: UPDATE", as_role("c", crud, "app_crud", "UPDATE accounts SET owner = 'dave' WHERE id = 3"), "ok")
    check("crud user: DELETE", as_role("c", crud, "app_crud", "DELETE FROM accounts WHERE id = 3"), "ok")
    check("crud user: CREATE TABLE", as_role("c", crud, "app_crud", "CREATE TABLE x (a int)"), "permission denied")
    check("crud user: DROP TABLE", as_role("c", crud, "app_crud", "DROP TABLE accounts"), "permission denied")

    check("admin user: CREATE TABLE", as_role("a", admin, "app_admin", "CREATE TABLE admin_made (a int)"), "ok")
    check("admin user: DROP TABLE it created", as_role("a", admin, "app_admin", "DROP TABLE admin_made"), "ok")

    print("logging in as a database user the role has no permission for")
    check("readonly role asks for the app_admin user", as_role("r", readonly, "app_admin", "SELECT 1"), "login refused")
    check("readonly role asks for the app_crud user", as_role("r", readonly, "app_crud", "SELECT 1"), "login refused")
    check("crud role asks for the app_admin user", as_role("c", crud, "app_admin", "SELECT 1"), "login refused")

    print("the Annexure C policies")
    for name in ("readonly", "crub", "admin"):
        env = assume("%s-annexure-%s" % (PREFIX, name))
        check("Annexure %s policy: log in as app_readonly" % name.upper(), as_role(name, env, "app_readonly", "SELECT 1"), "login refused")

    print("ModifyDBParameterGroup per role")
    for label, env in (("recommended set", readonly), ("Annexure ReadOnly", assume(PREFIX + "-annexure-readonly")),
                       ("Annexure CRUB", assume(PREFIX + "-annexure-crub")), ("Annexure Admin", assume(PREFIX + "-annexure-admin"))):
        ok, text = aws("rds", "modify-db-parameter-group", "--db-parameter-group-name", PG_NAME, "--parameters",
                       "ParameterName=log_min_duration_statement,ParameterValue=-1,ApplyMethod=immediate",
                       env=env, ok_fail=True)
        got = "OK" if ok else ("AccessDenied" if "AccessDenied" in text or "not authorized" in text else text[:60])
        check("%s: ModifyDBParameterGroup" % label, got, "OK" if label in ("Annexure CRUB", "Annexure Admin") else "AccessDenied")

    print("the CRUB role resets the master password, then logs in as the database owner")
    crub = assume(PREFIX + "-annexure-crub")
    new_password = secrets.token_urlsafe(18)
    ok, text = aws("rds", "modify-db-instance", "--db-instance-identifier", DB, "--apply-immediately",
                   "--master-user-password", new_password, env=crub, ok_fail=True)
    check("CRUB role: reset the master password", "OK" if ok else "AccessDenied", "OK")
    if ok:
        time.sleep(30)
        wait_for("password reset to finish", lambda: db_status() == "available", timeout=600)
        time.sleep(10)
        check("owner login with the new password: SELECT", classify(sql("dbadmin", new_password, "SELECT count(*) FROM accounts")), "ok")
        check("owner login with the new password: DROP TABLE", classify(sql("dbadmin", new_password, "DROP TABLE accounts")), "ok")


def cleanup():
    print("\ncleaning up...")

    def quiet(*args):
        aws(*args, ok_fail=True)
    if created["db"]:
        quiet("rds", "delete-db-instance", "--db-instance-identifier", DB, "--skip-final-snapshot", "--delete-automated-backups")
    for role in created["roles"]:
        quiet("iam", "delete-role-policy", "--role-name", role, "--policy-name", "under-test")
        quiet("iam", "delete-role", "--role-name", role)
    if created["db"]:
        try:
            wait_for("database to be deleted", lambda: db_status() == "gone", timeout=1500)
        except RuntimeError as err:
            print("WARNING:", err, "- check the RDS console for", DB)
    if created["pg"]:
        quiet("rds", "delete-db-parameter-group", "--db-parameter-group-name", PG_NAME)
    if created["sg"]:
        for _ in range(12):   # the group is busy until the database's network interface is gone
            ok, _text = aws("ec2", "delete-security-group", "--group-id", created["sg"], ok_fail=True)
            if ok:
                break
            time.sleep(15)
    print("cleanup done")


def main():
    try:
        setup()
        run_tests()
    finally:
        cleanup()
    print("\n%-70s %-18s %s" % ("check", "result", "expected"))
    bad = 0
    for label, got, want in results:
        bad += got != want
        print("[%s] %-65s %-18s %s" % ("ok  " if got == want else "FAIL", label, got, want))
    print("\n%s" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
