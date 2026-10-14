#!/usr/bin/env python3
"""Test how an AWS role trust policy treats an OIDC token, using GitHub Actions as the issuer.

The Azure DevOps to EKS pod to AWS role chain in Annexure B depends on one mechanism: a role that
trusts an OIDC token and pins its subject (and audience). EKS (IRSA) and Azure DevOps (workload
identity federation) both use it. The issuer here is GitHub Actions, whose tokens are real and
need no extra setup, so this tests the AWS side of that mechanism for real. It does not run Azure
DevOps or EKS themselves.

It creates an IAM OIDC provider and three roles, runs the manual workflow
.github/workflows/oidc-trust-test.yml on the default branch and on a throwaway branch, reads the
results from the workflow log, then deletes everything it created.

Roles: pinned to this repository's default branch (using the exact sub the token carries),
pinned to a different repository, and pinned with the classic sub format from older guides,
which no longer matches a repository whose subject carries numeric IDs. It also checks that AWS
refuses to create a GitHub trust policy with no sub condition or with a bare wildcard.

Usage: AWS_PROFILE=<admin profile> python3 aws-validation/real_oidc_trust_test.py   (needs gh, logged in)
"""
import json
import subprocess
import sys
import time

REGION = "eu-west-1"
PROVIDER_HOST = "token.actions.githubusercontent.com"
WORKFLOW = "oidc-trust-test.yml"
BRANCH = "oidc-trust-test-branch"
created = {"provider": None, "roles": [], "secret": False, "branch": False}
results = []


def sh(*cmd, ok_fail=False):
    for attempt in range(4):     # the GitHub API sometimes drops the connection; retry those
        proc = subprocess.run(cmd, capture_output=True, text=True)
        flaky = proc.returncode and any(m in proc.stderr for m in ("timed out", "Connection reset", "EOF", "TLS handshake"))
        if not flaky:
            break
        time.sleep(5)
    if ok_fail:
        return proc.returncode == 0, proc.stdout if proc.returncode == 0 else proc.stderr
    if proc.returncode:
        raise RuntimeError("%s failed: %s" % (" ".join(cmd[:3]), proc.stderr.strip()[:300]))
    return proc.stdout


def aws(*args, ok_fail=False):
    out = sh("aws", *args, "--region", REGION, "--output", "json", ok_fail=ok_fail)
    if ok_fail:
        return out
    return json.loads(out) if out.strip() else None


def trust(account, conditions, operator="StringEquals"):
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": "arn:aws:iam::%s:oidc-provider/%s" % (account, PROVIDER_HOST)},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {operator: conditions}}]})


def latest_run(repo, ref):
    runs = json.loads(sh("gh", "run", "list", "--repo", repo, "--workflow", WORKFLOW, "--branch", ref,
                         "--limit", "1", "--json", "databaseId"))
    return runs[0]["databaseId"] if runs else None


def run_workflow(repo, ref):
    before = latest_run(repo, ref)
    sh("gh", "workflow", "run", WORKFLOW, "--repo", repo, "--ref", ref)
    run_id = None
    for _ in range(40):          # wait for the new run to show up
        time.sleep(5)
        current = latest_run(repo, ref)
        if current and current != before:
            run_id = current
            break
    if run_id is None:
        raise RuntimeError("workflow run did not start")
    for _ in range(60):
        status = json.loads(sh("gh", "run", "view", str(run_id), "--repo", repo, "--json", "status"))["status"]
        if status == "completed":
            break
        time.sleep(5)
    log = sh("gh", "run", "view", str(run_id), "--repo", repo, "--log")
    found, subject = {}, None
    for line in log.splitlines():
        if "CLAIMS " in line and " sub=" in line:
            subject = line.split(" sub=", 1)[1].strip()
        if "RESULT " in line:
            parts = line.split("RESULT ", 1)[1].split()
            if len(parts) == 2:
                found[parts[0]] = parts[1]
    return found, subject


def run():
    account = aws("sts", "get-caller-identity")["Account"]
    repo = json.loads(sh("gh", "repo", "view", "--json", "nameWithOwner"))["nameWithOwner"]
    default_branch = json.loads(sh("gh", "repo", "view", "--json", "defaultBranchRef"))["defaultBranchRef"]["name"]
    print("repository", repo)

    ok, text = aws("iam", "get-open-id-connect-provider", "--open-id-connect-provider-arn",
                   "arn:aws:iam::%s:oidc-provider/%s" % (account, PROVIDER_HOST), ok_fail=True)
    if not ok:
        arn = aws("iam", "create-open-id-connect-provider", "--url", "https://" + PROVIDER_HOST,
                  "--client-id-list", "sts.amazonaws.com")["OpenIDConnectProviderArn"]
        created["provider"] = arn
    aud = {PROVIDER_HOST + ":aud": "sts.amazonaws.com"}
    sub = PROVIDER_HOST + ":sub"

    # GitHub's subject is not always repo:OWNER/REPO:ref:... Newer repositories get numeric IDs in it,
    # so ask a first workflow run what the token really says and build the trust policies from that.
    # a secret, not a variable, so GitHub masks the account ID in the (public) workflow logs
    sh("gh", "secret", "set", "AWS_TEST_ACCOUNT_ID", "--repo", repo, "--body", account)
    created["secret"] = True
    print("discovery run on", default_branch)
    _, real_subject = run_workflow(repo, default_branch)
    if not real_subject:
        raise RuntimeError("could not read the sub claim from the workflow log")
    owner, name = repo.split("/")
    other_repo_subject = real_subject.replace("/" + name, "/" + name + "-other", 1)
    results.append(("the sub claim carries numeric IDs (repo:owner@id/name@id...)", "@" in real_subject.split("/")[0], True))
    roles = {
        "oidc-test-pinned": trust(account, dict(aud, **{sub: real_subject})),
        "oidc-test-wrong-repo": trust(account, dict(aud, **{sub: other_repo_subject})),
        # the classic format from older guides, which no longer matches a repository with numeric IDs
        "oidc-test-classic-sub": trust(account, dict(aud, **{sub: "repo:%s:ref:refs/heads/%s" % (repo, default_branch)})),
    }
    for role_name, policy in roles.items():
        aws("iam", "create-role", "--role-name", role_name, "--assume-role-policy-document", policy)
        created["roles"].append(role_name)

    # two ways of leaving the subject open. AWS may refuse to create them, which is a result in itself.
    ok, text = aws("iam", "create-role", "--role-name", "oidc-test-unpinned", "--assume-role-policy-document",
                   trust(account, aud), ok_fail=True)
    results.append(("IAM accepts a GitHub trust policy with no sub condition at all",
                    "accepted" if ok else "refused", "refused"))
    if ok:
        aws("iam", "delete-role", "--role-name", "oidc-test-unpinned")
    star_created, star_text = aws("iam", "create-role", "--role-name", "oidc-test-unpinned", "--assume-role-policy-document",
                  json.dumps({"Version": "2012-10-17", "Statement": [{
                      "Effect": "Allow",
                      "Principal": {"Federated": "arn:aws:iam::%s:oidc-provider/%s" % (account, PROVIDER_HOST)},
                      "Action": "sts:AssumeRoleWithWebIdentity",
                      "Condition": {"StringEquals": aud, "StringLike": {sub: "*"}}}]}), ok_fail=True)
    results.append(("IAM accepts a GitHub trust policy with StringLike sub = *", "accepted" if star_created else "refused", "refused"))
    if star_created:
        created["roles"].append("oidc-test-unpinned")

    time.sleep(15)

    print("workflow on", default_branch)
    on_default, _ = run_workflow(repo, default_branch)
    sha = json.loads(sh("gh", "api", "repos/%s/git/ref/heads/%s" % (repo, default_branch)))["object"]["sha"]
    sh("gh", "api", "repos/%s/git/refs" % repo, "-f", "ref=refs/heads/" + BRANCH, "-f", "sha=" + sha)
    created["branch"] = True
    print("workflow on", BRANCH)
    on_branch, _ = run_workflow(repo, BRANCH)

    for label, found, wants in (
            ("default branch", on_default, {"pinned": "OK", "wrong-repo": "DENIED", "classic-sub": "DENIED", "pinned-wrong-audience": "DENIED"}),
            ("other branch", on_branch, {"pinned": "DENIED", "wrong-repo": "DENIED", "classic-sub": "DENIED", "pinned-wrong-audience": "DENIED"})):
        for role, want in wants.items():
            results.append(("workflow on the %s: role %s" % (label, role), found.get(role, "no result"), want))


def cleanup():
    print("\ncleaning up...")
    repo = json.loads(sh("gh", "repo", "view", "--json", "nameWithOwner"))["nameWithOwner"]
    if created["branch"]:
        sh("gh", "api", "-X", "DELETE", "repos/%s/git/refs/heads/%s" % (repo, BRANCH), ok_fail=True)
    if created["secret"]:
        sh("gh", "secret", "delete", "AWS_TEST_ACCOUNT_ID", "--repo", repo, ok_fail=True)
    for name in created["roles"]:
        aws("iam", "delete-role", "--role-name", name, ok_fail=True)
    if created["provider"]:
        aws("iam", "delete-open-id-connect-provider", "--open-id-connect-provider-arn", created["provider"], ok_fail=True)
    print("cleanup done")


def main():
    try:
        run()
    finally:
        cleanup()
    print("\n%-62s %-12s %s" % ("check", "result", "expected"))
    bad = 0
    for label, got, want in results:
        bad += got != want
        print("[%s] %-57s %-12s %s" % ("ok  " if got == want else "FAIL", label, got, want))
    print("\n%s" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
