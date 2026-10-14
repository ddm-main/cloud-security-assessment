#!/usr/bin/env python3
"""Test how AWS treats a real Microsoft Entra ID token in a role trust policy.

Annexure B's pipeline runs on Azure and has to get into AWS roles. One way is to let a role trust
an OIDC token issued by Entra ID. This test uses real Entra tokens (no client secret needed: the
token is the signed-in user's, requested with the Azure CLI) and checks what AWS does with them.

It creates an Entra app registration, an IAM OIDC provider for the token's issuer and a few roles,
tries AssumeRoleWithWebIdentity, and deletes everything again. Tokens are never printed, only a few
non-secret claims.

Entra can issue two token formats for the same app. The format is a setting on the app:
  --token-version 1   issuer https://sts.windows.net/<tenant>/, audience api://<app id>
  --token-version 2   issuer https://login.microsoftonline.com/<tenant>/v2.0, audience <app id>
AWS accepted v1 tokens and rejected v2 tokens as "could not be validated" in every run.

Needs: az login (to a tenant where you may create app registrations), an AWS admin profile.
Usage: AWS_PROFILE=<admin profile> python3 aws-validation/real_entra_oidc_test.py [--token-version 1|2]
"""
import argparse
import base64
import json
import subprocess
import sys
import time
import uuid

REGION = "eu-west-1"
APP_NAME = "aws-oidc-test"
AZURE_CLI_APP_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # the Azure CLI's own application ID
created = {"app": None, "provider": None, "roles": []}
results = []
printed = []


def run(cmd, ok_fail=False):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if ok_fail:
        return proc.returncode == 0, proc.stdout if proc.returncode == 0 else proc.stderr
    if proc.returncode:
        raise RuntimeError("%s failed: %s" % (" ".join(cmd[:3]), proc.stderr.strip()[:400]))
    return proc.stdout


def az(*args, ok_fail=False):
    out = run(["az", *args, "--only-show-errors"], ok_fail)
    return out if ok_fail else out.strip()


def aws(*args, ok_fail=False):
    out = run(["aws", *args, "--region", REGION, "--output", "json"], ok_fail)
    if ok_fail:
        return out
    return json.loads(out) if out.strip() else None


def claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def get_token(resource):
    ok, out = az("account", "get-access-token", "--resource", resource, "--query", "accessToken", "-o", "tsv", ok_fail=True)
    if not ok or not out.strip():
        raise RuntimeError("could not get a token for %s: %s" % (resource, out.strip()[:300]))
    return out.strip()


def create_app(token_version):
    app = json.loads(az("ad", "app", "create", "--display-name", APP_NAME, "--sign-in-audience", "AzureADMyOrg", "-o", "json"))
    created["app"] = app["id"]
    app_id = app["appId"]
    az("ad", "app", "update", "--id", app_id, "--identifier-uris", "api://" + app_id)
    scope_id = str(uuid.uuid4())
    api = {"requestedAccessTokenVersion": token_version,
           "oauth2PermissionScopes": [{
               "id": scope_id, "isEnabled": True, "type": "User", "value": "access_as_user",
               "adminConsentDisplayName": "Test access", "adminConsentDescription": "Test access to the AWS OIDC test app",
               "userConsentDisplayName": "Test access", "userConsentDescription": "Test access to the AWS OIDC test app"}]}
    az("ad", "app", "update", "--id", app_id, "--set", "api=" + json.dumps(api))
    time.sleep(8)
    # let the Azure CLI ask for this app's token without a consent prompt
    api["preAuthorizedApplications"] = [{"appId": AZURE_CLI_APP_ID, "delegatedPermissionIds": [scope_id]}]
    az("ad", "app", "update", "--id", app_id, "--set", "api=" + json.dumps(api))
    az("ad", "sp", "create", "--id", app_id)
    time.sleep(25)
    return app_id


def assume(role_arn, token):
    ok, out = aws("sts", "assume-role-with-web-identity", "--no-sign-request", "--role-arn", role_arn,
                  "--role-session-name", "entra-test", "--web-identity-token", token, ok_fail=True)
    if ok:
        return "assumed"
    if "InvalidIdentityToken" in out:
        return "InvalidIdentityToken"
    if "AccessDenied" in out:
        return "denied"
    return "other: " + out.strip().splitlines()[-1][:80]


def assume_with_retry(role_arn, token, tries):
    """A new OIDC provider can take a little while before AWS accepts tokens for it."""
    got = assume(role_arn, token)
    for _ in range(tries - 1):
        if got != "InvalidIdentityToken":
            break
        time.sleep(20)
        got = assume(role_arn, token)
    return got


def run_tests(token_version):
    app_id = create_app(token_version)
    token = None
    for _ in range(6):
        try:
            token = get_token("api://" + app_id)
            break
        except RuntimeError as err:
            last_error = err
            time.sleep(15)
    if token is None:
        raise last_error

    c = claims(token)
    shown = {key: c.get(key) for key in ("ver", "iss", "aud", "sub", "oid", "tid", "scp", "amr")}
    shown["lifetime_minutes"] = (c["exp"] - c["iat"]) // 60
    printed.append(("claims in the access token", shown))

    provider = aws("iam", "create-open-id-connect-provider", "--url", c["iss"], "--client-id-list", c["aud"])["OpenIDConnectProviderArn"]
    created["provider"] = provider
    host = c["iss"].replace("https://", "")
    account = aws("sts", "get-caller-identity")["Account"]

    def make_role(name, conditions):
        policy = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Federated": provider},
            "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": conditions}}]})
        ok, out = aws("iam", "create-role", "--role-name", name, "--assume-role-policy-document", policy, ok_fail=True)
        if ok:
            created["roles"].append(name)
            return "arn:aws:iam::%s:role/%s" % (account, name)
        if "MalformedPolicyDocument" in out:
            return None
        raise RuntimeError(out[:200])

    audience = {host + ":aud": c["aud"]}
    pinned = make_role("entra-test-pinned", dict(audience, **{host + ":sub": c["sub"]}))
    other_sub = make_role("entra-test-other-sub", dict(audience, **{host + ":sub": "not-this-user"}))
    audience_only = make_role("entra-test-audience-only", audience)
    results.append(("IAM accepts a trust policy with only an audience condition (no sub)",
                    "accepted" if audience_only else "refused", "accepted"))
    time.sleep(20)

    works = "assumed" if token_version == 1 else "InvalidIdentityToken"
    denied_by_sub = "denied" if token_version == 1 else "InvalidIdentityToken"
    tries = 10 if token_version == 1 else 3
    results.append(("role pinned to the exact sub and aud", assume_with_retry(pinned, token, tries), works))
    results.append(("role pinned to a different sub", assume(other_sub, token), denied_by_sub))
    if audience_only:
        results.append(("role with audience only (any user who can get a token for the app)", assume(audience_only, token), works))
    graph = get_token("https://graph.microsoft.com")
    results.append(("pinned role, token issued for another audience (Graph)", assume(pinned, graph), "InvalidIdentityToken"))


def cleanup():
    print("\ncleaning up...")
    for name in created["roles"]:
        aws("iam", "delete-role", "--role-name", name, ok_fail=True)
    if created["provider"]:
        aws("iam", "delete-open-id-connect-provider", "--open-id-connect-provider-arn", created["provider"], ok_fail=True)
    if created["app"]:
        az("ad", "app", "delete", "--id", created["app"], ok_fail=True)
    print("cleanup done")


def main():
    parser = argparse.ArgumentParser(description="Test Entra ID tokens against an AWS role trust policy.")
    parser.add_argument("--token-version", type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    try:
        run_tests(args.token_version)
    finally:
        cleanup()
    for title, data in printed:
        print("\n%s (token version %d):" % (title, args.token_version))
        for key, value in data.items():
            print("  %-17s %s" % (key, value))
    print("\n%-72s %-22s %s" % ("check", "result", "expected"))
    bad = 0
    for label, got, want in results:
        bad += got != want
        print("[%s] %-67s %-22s %s" % ("ok  " if got == want else "FAIL", label, got, want))
    print("\n%s (%d checks)" % ("ALL CHECKS AS EXPECTED" if not bad else "%d CHECK(S) DID NOT MATCH" % bad, len(results)))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
