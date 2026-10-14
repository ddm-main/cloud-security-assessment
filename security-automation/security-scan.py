#!/usr/bin/env python3
"""Run SAST, dependency, secrets and IaC scans on a path and print one PASS/FAIL verdict.

Each scan has an external tool (semgrep, osv-scanner, gitleaks, checkov) and a small
set of built-in rules. If the tool is installed both run and the results are merged,
otherwise only the built-in rules run.

Exit code: 0 = PASS, 1 = FAIL, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RANK = {name: i for i, name in enumerate(SEVERITIES)}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", "dist", "build"}
MAX_FILE_SIZE = 1_000_000
IGNORE_MARKER = "security-scan:ignore"


@dataclass
class Finding:
    category: str          # sast, dependency, secrets or iac
    tool: str
    rule_id: str
    severity: str
    message: str
    file: str = ""
    line: int = 0


@dataclass
class ScanResult:
    category: str
    tool: str
    status: str            # ok or error
    duration_s: float = 0.0
    detail: str = ""
    findings: List[Finding] = field(default_factory=list)


# ---------------------------------------------------------------- helpers

def normalize_severity(value) -> str:
    value = (value or "").upper()
    aliases = {"ERROR": "HIGH", "WARNING": "MEDIUM", "MODERATE": "MEDIUM"}
    value = aliases.get(value, value)
    return value if value in RANK else "MEDIUM"


def walk(root: Path):
    """Yield every regular file under root, skipping vendored dirs, symlinks and big files."""
    if root.is_file():
        yield root
        return
    for folder, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            path = Path(folder) / name
            try:
                if path.is_symlink() or path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield path


def read_lines(path: Path) -> List[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if b"\0" in data[:2048]:   # binary file
        return []
    return data.decode("utf-8", errors="replace").splitlines()


def relative(path, root: Path) -> str:
    """Path relative to the scan root, so every tool reports files the same way."""
    if not path:
        return ""
    base = root if root.is_dir() else root.parent
    try:
        return str(Path(path).resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def run(cmd: List[str], timeout: int, ok_codes=(0, 1)) -> subprocess.CompletedProcess:
    # The command is a list and never goes through a shell, so the scanned path can't inject anything.
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode not in ok_codes:
        lines = proc.stderr.strip().splitlines()
        last_line = lines[-1][:200] if lines else "no output"
        raise RuntimeError("%s exited with %d: %s" % (cmd[0], proc.returncode, last_line), proc.returncode)
    return proc


# ---------------------------------------------------------------- SAST

SAST_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php"}

SAST_RULES = [
    ("SAST-EVAL", "HIGH",
     r"(?<![\w.])(eval|exec)\s*\(",
     "Dynamic code execution (eval/exec)"),
    ("SAST-SHELL", "HIGH",
     r"subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\s*\(",
     "Shell command execution, possible command injection"),
    ("SAST-PICKLE", "HIGH",
     r"\bpickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader=(?:yaml\.)?Safe)",
     "Unsafe deserialization"),
    ("SAST-SQLI", "HIGH",
     r"(?i)\.execute\s*\(\s*(f[\"']|[\"'][^\"']*(select|insert|update|delete)[^\"']*[\"']\s*(%|\+|\.format))",
     "SQL query built with string formatting, possible SQL injection"),
    ("SAST-WEAKHASH", "MEDIUM",
     r"hashlib\.(md5|sha1)\s*\(|createHash\(['\"](md5|sha1)['\"]\)",
     "Weak hash algorithm"),
    ("SAST-TLS-OFF", "HIGH",
     r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true",
     "TLS certificate verification turned off"),
    ("SAST-DEBUG", "MEDIUM",
     r"app\.run\([^)]*debug\s*=\s*True",
     "Flask debug mode enabled"),
    ("SAST-INNERHTML", "MEDIUM",
     r"\.innerHTML\s*=|document\.write\s*\(",
     "DOM XSS sink"),
]
SAST_RULES = [(rid, sev, re.compile(rx), msg) for rid, sev, rx, msg in SAST_RULES]


def sast_builtin(root: Path) -> ScanResult:
    findings = []
    for path in walk(root):
        if path.suffix not in SAST_EXTENSIONS:
            continue
        for number, line in enumerate(read_lines(path), 1):
            if IGNORE_MARKER in line or line.lstrip().startswith(("#", "//")):
                continue
            for rule_id, severity, regex, message in SAST_RULES:
                if regex.search(line):
                    findings.append(Finding("sast", "builtin-sast", rule_id, severity, message,
                                            relative(path, root), number))
    return ScanResult("sast", "builtin-sast", "ok", findings=findings)


def sast_semgrep(root: Path) -> ScanResult:
    cmd = ["semgrep", "scan", "--config", "p/default", "--metrics", "off", "--json", "--quiet", str(root)]
    data = json.loads(run(cmd, 600).stdout or "{}")
    findings = []
    for hit in data.get("results", []):
        extra = hit.get("extra", {})
        message = " ".join(extra.get("message", "").split())[:160]
        findings.append(Finding("sast", "semgrep", hit.get("check_id", "semgrep"),
                                normalize_severity(extra.get("severity")), message,
                                relative(hit.get("path"), root), hit.get("start", {}).get("line", 0)))
    return ScanResult("sast", "semgrep", "ok", findings=findings)


# ---------------------------------------------------------------- dependencies

# A few well known bad versions so the built-in check has something to find.
# osv-scanner is the real source of truth.
# (ecosystem, name) -> (first safe version, advisory text, severity)
OLD_VERSIONS = {
    ("pypi", "django"): ("3.2.5", "CVE-2021-35042 (SQL injection in order_by)", "CRITICAL"),
    ("pypi", "flask"): ("2.2.5", "CVE-2023-30861 (session cookie disclosure)", "HIGH"),
    ("pypi", "pyyaml"): ("5.4", "CVE-2020-14343 (arbitrary code execution)", "CRITICAL"),
    ("pypi", "requests"): ("2.31.0", "CVE-2023-32681 (proxy header leak)", "MEDIUM"),
    ("pypi", "jinja2"): ("3.1.3", "CVE-2024-22195 (XSS in xmlattr)", "MEDIUM"),
    ("npm", "lodash"): ("4.17.21", "CVE-2021-23337 (command injection)", "HIGH"),
    ("npm", "minimist"): ("1.2.6", "CVE-2021-44906 (prototype pollution)", "CRITICAL"),
    ("npm", "express"): ("4.19.2", "CVE-2024-29041 (open redirect)", "MEDIUM"),
}


def version_tuple(text: str):
    return tuple(int(n) for n in re.findall(r"\d+", text)[:4]) or (0,)


def pinned_packages(path: Path):
    """Return (ecosystem, name, version, line) for pinned deps in requirements*.txt and package.json."""
    pins = []
    if path.name.startswith("requirements") and path.suffix == ".txt":
        for number, line in enumerate(read_lines(path), 1):
            match = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.]*)", line)
            if match:
                pins.append(("pypi", match.group(1).lower(), match.group(2), number))
    elif path.name == "package.json":
        try:
            package = json.loads("\n".join(read_lines(path)))
        except ValueError:
            return pins
        for section in ("dependencies", "devDependencies"):
            for name, spec in (package.get(section) or {}).items():
                match = re.search(r"\d+(\.\d+)*", str(spec))
                if match:
                    pins.append(("npm", name.lower(), match.group(0), 0))
    return pins


def dependency_builtin(root: Path) -> ScanResult:
    findings = []
    for path in walk(root):
        for ecosystem, name, version, number in pinned_packages(path):
            known = OLD_VERSIONS.get((ecosystem, name))
            if not known:
                continue
            safe_version, advisory, severity = known
            if version_tuple(version) < version_tuple(safe_version):
                message = "%s %s is vulnerable: %s, upgrade to %s or later" % (name, version, advisory, safe_version)
                findings.append(Finding("dependency", "builtin-deps", advisory.split(" ")[0], severity,
                                        message, relative(path, root), number))
    return ScanResult("dependency", "builtin-deps", "ok", findings=findings,
                      detail="built-in check uses a small offline advisory list")


def cvss_to_severity(score) -> str:
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"        # advisory has no score
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def dependency_osv(root: Path) -> ScanResult:
    cmd = ["osv-scanner", "scan", "source", "--format", "json"]
    if root.is_file():
        cmd += ["-L", str(root)]
    else:
        cmd += ["-r", "--allow-no-lockfiles", str(root)]
    try:
        data = json.loads(run(cmd, 600).stdout or "{}")
    except RuntimeError as err:
        # osv exits 127/128 when it is pointed at a file it doesn't understand
        if root.is_file() and err.args[1] in (127, 128):
            return ScanResult("dependency", "osv-scanner", "ok", detail="not a dependency file")
        raise

    findings = []
    for result in data.get("results") or []:
        source = relative(result.get("source", {}).get("path") or ".", root)
        for pkg in result.get("packages") or []:
            name = pkg.get("package", {}).get("name", "?")
            version = pkg.get("package", {}).get("version", "?")
            summaries = {v.get("id"): v.get("summary") for v in pkg.get("vulnerabilities") or []}
            # osv groups advisories about the same issue (PYSEC-..., GHSA-..., CVE-...)
            for group in pkg.get("groups") or []:
                ids = group.get("ids") or []
                aliases = group.get("aliases") or ids
                rule_id = next((a for a in aliases if a.startswith("CVE-")), ids[0] if ids else "OSV")
                summary = next((summaries[i] for i in ids if summaries.get(i)), "known vulnerability")
                findings.append(Finding("dependency", "osv-scanner", rule_id,
                                        cvss_to_severity(group.get("max_severity")),
                                        ("%s %s: %s" % (name, version, summary))[:240], source))
    return ScanResult("dependency", "osv-scanner", "ok", findings=findings)


# ---------------------------------------------------------------- secrets

SECRET_RULES = [
    ("SECRET-AWS-KEY", "CRITICAL", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key ID"),
    ("SECRET-PRIVATE-KEY", "CRITICAL",
     r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "Private key"),
    ("SECRET-GITHUB", "CRITICAL", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token"),
    ("SECRET-SLACK", "HIGH", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    ("SECRET-GENERIC", "HIGH",
     r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b[\"']?\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
     "Hard-coded credential"),
]
SECRET_RULES = [(rid, sev, re.compile(rx), msg) for rid, sev, rx, msg in SECRET_RULES]

# lines that look like docs or templates rather than real credentials
PLACEHOLDER = re.compile(r"(?i)example|changeme|placeholder|your[_-]|<.*>|\$\{|xxxx|dummy")


def secrets_builtin(root: Path) -> ScanResult:
    findings = []
    for path in walk(root):
        for number, line in enumerate(read_lines(path), 1):
            if IGNORE_MARKER in line:
                continue
            for rule_id, severity, regex, message in SECRET_RULES:
                if not regex.search(line):
                    continue
                if rule_id == "SECRET-GENERIC" and PLACEHOLDER.search(line):
                    continue
                findings.append(Finding("secrets", "builtin-secrets", rule_id, severity, message,
                                        relative(path, root), number))
                break          # one finding per line is enough
    return ScanResult("secrets", "builtin-secrets", "ok", findings=findings)


def secrets_gitleaks(root: Path) -> ScanResult:
    options = ["--report-format", "json", "--exit-code", "0", "--redact", "--no-banner"]
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        options += ["--report-path", str(report)]
        try:
            run(["gitleaks", "dir", str(root)] + options, 600)
        except RuntimeError:
            # gitleaks older than 8.19 has no "dir" command
            run(["gitleaks", "detect", "--no-git", "--source", str(root)] + options, 600)
        leaks = json.loads(report.read_text() or "[]") if report.exists() else []
    findings = [Finding("secrets", "gitleaks", leak.get("RuleID", "gitleaks"), "CRITICAL",
                        leak.get("Description", "secret"), relative(leak.get("File"), root),
                        leak.get("StartLine", 0))
                for leak in leaks]       # the secret itself is redacted and never stored
    return ScanResult("secrets", "gitleaks", "ok", findings=findings)


# ---------------------------------------------------------------- IaC

IAC_EXTENSIONS = {".tf", ".yaml", ".yml", ".json", ".template"}

IAC_RULES = [
    ("IAC-S3-PUBLIC-ACL", "HIGH",
     r"(?i)acl\s*[=:]\s*[\"']?public-read(-write)?", "S3 bucket with a public ACL"),
    ("IAC-SG-OPEN", "HIGH",
     r"0\.0\.0\.0/0", "Open to the whole internet (0.0.0.0/0)"),
    ("IAC-IAM-WILDCARD", "HIGH",
     r"(?i)[\"']?action[\"']?\s*[=:]\s*\[?\s*[\"']\*[\"']", "IAM policy with Action *"),
    ("IAC-ENC-OFF", "MEDIUM",
     r"(?i)(storage_encrypted|encrypted|kms_encrypted)\s*[=:]\s*[\"']?false", "Encryption disabled"),
    ("IAC-RDS-PUBLIC", "HIGH",
     r"(?i)publicly_accessible\s*[=:]\s*[\"']?true|PubliclyAccessible[\"']?\s*:\s*[\"']?true",
     "RDS instance is publicly accessible"),
    ("IAC-IMDSV1", "MEDIUM",
     r"(?i)http_tokens\s*=\s*\"optional\"", "EC2 allows IMDSv1"),
]
IAC_RULES = [(rid, sev, re.compile(rx), msg) for rid, sev, rx, msg in IAC_RULES]


def iac_builtin(root: Path) -> ScanResult:
    findings = []
    for path in walk(root):
        if path.suffix not in IAC_EXTENSIONS:
            continue
        if path.name == "package.json" or path.name.startswith("package-lock"):
            continue
        for number, line in enumerate(read_lines(path), 1):
            if IGNORE_MARKER in line:
                continue
            for rule_id, severity, regex, message in IAC_RULES:
                if regex.search(line):
                    findings.append(Finding("iac", "builtin-iac", rule_id, severity, message,
                                            relative(path, root), number))
    return ScanResult("iac", "builtin-iac", "ok", findings=findings)


def iac_checkov(root: Path) -> ScanResult:
    cmd = ["checkov", "-f" if root.is_file() else "-d", str(root), "-o", "json", "--quiet", "--compact"]
    data = json.loads(run(cmd, 900).stdout.strip() or "[]")
    reports = data if isinstance(data, list) else [data]    # one report per framework
    base = root.parent if root.is_file() else root
    findings = []
    for report in reports:
        for check in (report.get("results") or {}).get("failed_checks", []):
            path = relative(base / (check.get("file_path") or "").lstrip("/"), root)
            findings.append(Finding("iac", "checkov", check.get("check_id", "CKV"),
                                    normalize_severity(check.get("severity")),
                                    check.get("check_name", ""), path,
                                    (check.get("file_line_range") or [0])[0]))
    return ScanResult("iac", "checkov", "ok", findings=findings)


# ---------------------------------------------------------------- running the scans

# scan name -> (tool binary, function that runs the tool, built-in function)
ENGINES: Dict[str, tuple] = {
    "sast": ("semgrep", sast_semgrep, sast_builtin),
    "dependency": ("osv-scanner", dependency_osv, dependency_builtin),
    "secrets": ("gitleaks", secrets_gitleaks, secrets_builtin),
    "iac": ("checkov", iac_checkov, iac_builtin),
}


def run_scan(name: str, root: Path, builtin_only: bool, require_tools: bool = False) -> ScanResult:
    """Run the external tool (if installed) and the built-in rules, then merge the findings.

    Both run on purpose: gitleaks, for example, skips AWS's documented example key,
    and the built-in rule still catches it.

    With require_tools, a missing or crashed external tool makes this scan an error
    instead of a note, so the run fails.
    """
    binary, external, builtin = ENGINES[name]
    started = time.time()
    parts: List[ScanResult] = []
    notes: List[str] = []
    tool_problem = False

    if not builtin_only:
        if shutil.which(binary):
            try:
                parts.append(external(root))
            except Exception as err:    # crash, timeout, bad output: note it and carry on
                reason = err.args[0] if isinstance(err, RuntimeError) else type(err).__name__
                notes.append("%s failed (%s)" % (binary, reason))
                tool_problem = True
        else:
            notes.append("%s not installed" % binary)
            tool_problem = True

    try:
        parts.append(builtin(root))
    except Exception as err:
        parts.append(ScanResult(name, "builtin", "error", detail=str(err)[:200]))

    merged: Dict[tuple, Finding] = {}
    for part in parts:
        for f in part.findings:
            # Two tools reporting the same thing count once. Dependencies match on CVE + file,
            # everything else on file + line. Keep the more severe one.
            if f.category == "dependency":
                key = (f.category, f.rule_id, f.file)
            else:
                key = (f.category, f.file, f.line)
            old = merged.get(key)
            if old is None or (RANK[f.severity], f.line > 0) > (RANK[old.severity], old.line > 0):
                merged[key] = f

    status = "error" if all(p.status == "error" for p in parts) else "ok"
    if require_tools and tool_problem:
        status = "error"
    tools = "+".join(p.tool for p in parts)
    detail = "; ".join(notes + [p.detail for p in parts if p.detail])
    return ScanResult(name, tools, status, round(time.time() - started, 2), detail, list(merged.values()))


def build_report(root: Path, results: List[ScanResult], fail_on: str) -> dict:
    findings = [f for r in results for f in r.findings]
    findings.sort(key=lambda f: (-RANK[f.severity], f.category, f.file, f.line))

    by_severity = {name: 0 for name in SEVERITIES}
    for f in findings:
        by_severity[f.severity] += 1

    blocking = [f for f in findings if RANK[f.severity] >= RANK[fail_on]]
    broken = [r for r in results if r.status == "error"]

    reasons = []
    if blocking:
        reasons.append("%d finding(s) at or above %s" % (len(blocking), fail_on))
    if broken:
        # a scan that could not run says nothing about the code, so it must not pass
        reasons.append("scanner error: " + ", ".join(r.category for r in broken))

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(root),
        "decision": "FAIL" if reasons else "PASS",
        "reason": "; ".join(reasons) or "no findings at or above %s" % fail_on,
        "fail_on": fail_on,
        "summary": {"total": len(findings), "by_severity": by_severity},
        "scans": [{"category": r.category, "tool": r.tool, "status": r.status, "duration_s": r.duration_s,
                   "detail": r.detail, "findings": len(r.findings)} for r in results],
        "findings": [asdict(f) for f in findings],
    }


# ---------------------------------------------------------------- output

def as_text(report: dict) -> str:
    out = ["Security scan: %s" % report["target"], ""]
    for scan in report["scans"]:
        out.append("  [%-10s] %-16s %-7s %d finding(s)  %s" % (
            scan["category"], scan["tool"], scan["status"], scan["findings"], scan["detail"]))
    out.append("")
    for f in report["findings"]:
        where = "%s:%s" % (f["file"], f["line"]) if f["file"] else "-"
        out.append("  %-8s %-18s %s  %s" % (f["severity"], f["rule_id"], where, f["message"]))
    counts = ", ".join("%s=%d" % (k, v) for k, v in report["summary"]["by_severity"].items() if v)
    out += ["", "Totals: " + (counts or "none"), "DECISION: %s (%s)" % (report["decision"], report["reason"])]
    return "\n".join(out)


def as_sarif(report: dict) -> dict:
    levels = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    results = []
    for f in report["findings"]:
        results.append({
            "ruleId": f["rule_id"],
            "level": levels[f["severity"]],
            "message": {"text": "[%s] %s" % (f["tool"], f["message"])},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
                "region": {"startLine": max(f["line"], 1)},
            }}],
        })
    return {"version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "security-scan"}}, "results": results}]}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run SAST, dependency, secrets and IaC scans and give one PASS/FAIL.")
    parser.add_argument("--path", required=True, help="file or folder to scan")
    parser.add_argument("--format", choices=["json", "text", "sarif"], default="text")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="HIGH",
                        help="lowest severity that fails the scan (default: HIGH)")
    parser.add_argument("--scans", default=",".join(ENGINES), help="comma separated: " + ", ".join(ENGINES))
    parser.add_argument("--builtin-only", action="store_true", help="don't use external tools")
    parser.add_argument("--require-tools", action="store_true",
                        help="fail if semgrep, osv-scanner, gitleaks or checkov is missing or crashes")
    parser.add_argument("--output", help="write the report to this file instead of printing it")
    args = parser.parse_args(argv)

    if args.require_tools and args.builtin_only:
        parser.error("--require-tools and --builtin-only cannot be used together")

    root = Path(args.path)
    if not root.exists():
        print("error: path not found: %s" % args.path, file=sys.stderr)
        return 2

    names = [n.strip() for n in args.scans.split(",") if n.strip()]
    unknown = [n for n in names if n not in ENGINES]
    if not names or unknown:
        print("error: unknown scan(s): %s" % (", ".join(unknown) or "(none given)"), file=sys.stderr)
        return 2

    # the scans don't depend on each other; map() keeps them in the order requested
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        results = list(pool.map(lambda n: run_scan(n, root, args.builtin_only, args.require_tools), names))
    report = build_report(root, results, args.fail_on)

    if args.format == "json":
        text = json.dumps(report, indent=2)
    elif args.format == "sarif":
        text = json.dumps(as_sarif(report), indent=2)
    else:
        text = as_text(report)

    if args.output:
        Path(args.output).write_text(text + "\n")
    else:
        print(text)
    return 0 if report["decision"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
