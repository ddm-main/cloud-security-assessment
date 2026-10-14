# security-automation

`security-scan.py` runs four kinds of security scan on a path (SAST, dependency check, secrets, IaC), merges the results into one report and gives a single PASS or FAIL.

| Scan | External tool (used if installed) | Built-in rules (always run) |
|---|---|---|
| SAST | semgrep | eval/exec, `shell=True`, SQL built with string formatting, unsafe deserialization, weak hashes, TLS verification off |
| Dependencies | osv-scanner | versions pinned in `requirements.txt` / `package.json` checked against a small offline list |
| Secrets | gitleaks | AWS keys, private keys, GitHub and Slack tokens, hard-coded passwords |
| IaC | checkov | public S3 ACL, `0.0.0.0/0`, `Action: *`, public RDS, encryption off, IMDSv1 |

Needs Python 3.8+ and nothing else. The external tools are optional. If one is on the PATH, it runs next to the built-in rules and the results are merged. I run both on purpose: gitleaks, for example, ignores AWS's documented example key, and the built-in rule still catches it.

```bash
brew install gitleaks osv-scanner
pip install semgrep checkov        # best inside a virtualenv
```

Semgrep runs with the `p/default` ruleset and `--metrics off`. It needs internet access to download the rules.

## Usage

```bash
./security-scan.py --path ./app --format json
./security-scan.py --path ./app                          # text report
./security-scan.py --path ./app --format sarif --output results.sarif
./security-scan.py --path ./app --fail-on CRITICAL       # default is HIGH
./security-scan.py --path ./app --scans secrets,iac      # only some scans
./security-scan.py --path ./app --builtin-only           # ignore external tools
./security-scan.py --path ./app --require-tools          # fail if any external tool is missing or crashes
```

Exit code is `0` for PASS, `1` for FAIL and `2` for bad usage, so it can gate a pipeline directly:

```bash
./security-scan.py --path . || exit 1
```

## Examples

```bash
./security-scan.py --path examples/vulnerable-app   # FAIL, exit 1
./security-scan.py --path examples/clean-app        # PASS, exit 0
```

| Run | vulnerable-app | clean-app |
|---|---|---|
| Built-in rules only | FAIL, 11 findings | PASS, 0 findings |
| With all four tools | FAIL, 23 findings (3 critical, 7 high, 13 medium) | PASS, 2 medium |

JSON output looks like this:

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-10-14T11:21:29+00:00",
  "decision": "FAIL",
  "reason": "10 finding(s) at or above HIGH",
  "fail_on": "HIGH",
  "summary": {"total": 23, "by_severity": {"CRITICAL": 3, "HIGH": 7, "MEDIUM": 13, "LOW": 0, "INFO": 0}},
  "scans": [{"category": "secrets", "tool": "gitleaks+builtin-secrets", "status": "ok", "findings": 1, "detail": ""}],
  "findings": [{"category": "secrets", "tool": "builtin-secrets", "rule_id": "SECRET-AWS-KEY",
                "severity": "CRITICAL", "message": "AWS access key ID", "file": "app.py", "line": 6}]
}
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The 22 tests run with `--builtin-only`, so they need no network. They cover:

- the vulnerable app fails and hits all four categories, the clean app passes
- the `--fail-on` threshold and inline suppression
- placeholder values like `your_api_key_here` are not flagged
- secret values never appear in the report
- a scanner error fails the run instead of passing silently
- an external tool failing is reported and the built-in rules still run
- merging keeps the more severe finding when two tools report the same line
- empty folder, single file, path with spaces, bad path, empty `--scans`
- `model.eval()` and `cursor.execute(q, p)` are not flagged
- `--require-tools` fails on a missing tool, is quiet when tools are present, and cannot be combined with `--builtin-only`
- SARIF output
- CVSS score to severity mapping, scans reported in the requested order, schema version and timestamp in the report

## Notes on the design

- **Fails closed.** If every engine for a scan crashes, the run fails. "Could not scan" is not treated as "clean". By default a missing external tool is only a note in the report, because the built-in rules still ran. Use `--require-tools` in CI so a missing or crashed scanner fails the build.
- **No duplicates.** When two tools flag the same file and line, or the same CVE in the same dependency file, only the more severe one is kept. osv-scanner results are grouped so one issue listed as PYSEC, GHSA and CVE is reported once, and its severity comes from the CVSS score.
- **Fast.** The four scans run in parallel.
- **CI.** `.github/workflows/security-scan.yml` in the repo root has two jobs. One runs the tests and the built-in rules. The other installs the real scanners (pinned versions, gitleaks and osv-scanner checksum-verified) and runs the examples with `--require-tools`: the clean example must pass, and the vulnerable one must fail with all four scans running, so a broken scanner cannot look like a pass.
- **Safe invocation.** Tools are started with an argument list, never through a shell, and gitleaks runs with `--redact`, so secret values never reach the report.
- **Suppression.** Put `security-scan:ignore` on a line to skip the built-in rules for it.
- **Limits.** The built-in rules are line-based regexes and the dependency list is only a sample. They are a safety net, not a replacement for the real tools. To add a rule, extend the `*_RULES` tables in the script.
