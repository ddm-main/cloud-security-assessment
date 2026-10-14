# Cloud Security Technical Assessment

| Question | Folder | What is in it |
|---|---|---|
| 1. Security automation | [security-automation/](security-automation/) | `security-scan.py` runs SAST, dependency, secrets and IaC scans and gives one PASS/FAIL. README, example apps, tests. |
| 2. Risk review | [risk-review/](risk-review/) | Reviews of the SSM automation policy and the RDS role policies, with replacement policies. |
| 3. Region SCP | [required-scp/](required-scp/) | SCP that restricts AWS to eu-west-1, with the reasoning and how to deploy it. |
| Evidence | [aws-validation/](aws-validation/) | Scripts that test the SCPs and policies against a real AWS account, and their results. |

## Quick start

```bash
# Question 1
./security-automation/security-scan.py --path ./security-automation/examples/vulnerable-app   # FAIL, exit 1
./security-automation/security-scan.py --path ./security-automation/examples/clean-app        # PASS, exit 0
python3 -m unittest discover -s security-automation/tests
```

The scanner works with nothing installed (built-in rules). Install semgrep, osv-scanner, gitleaks and checkov to get the full result; see the README in `security-automation/`.

Questions 2 and 3 are documents and policy files. Start with `risk-review/README.md` and `required-scp/README.md`.
