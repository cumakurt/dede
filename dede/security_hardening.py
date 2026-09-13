"""High-precision security hardening checks that complement taint analysis.

These checks target API/configuration facts that are dangerous without needing a
source-to-sink proof (for example TLS verification being explicitly disabled).
The analyzer is intentionally conservative: generic weak-algorithm names are not
reported unless the usage itself proves a security-sensitive misuse.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from dede.analyzers.base import Analyzer
from dede.config import AppConfig
from dede.models import (
    AnalyzerResult,
    Category,
    Confidence,
    Evidence,
    Finding,
    Precision,
    ProjectContext,
    Severity,
    ToolStatus,
)


@dataclass(frozen=True)
class HardeningRule:
    id: str
    extensions: tuple[str, ...]
    regex: str
    message: str
    recommendation: str
    cwe: str
    severity: Severity = Severity.HIGH
    precision: Precision = Precision.VERY_HIGH
    masked: bool = False


_RULES: tuple[HardeningRule, ...] = (
    # TLS / certificate validation -------------------------------------------------
    HardeningRule("dede.hardening.python.tls-verify-false", (".py",), r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete|request)\s*\([^\n]*\bverify\s*=\s*False\b", "TLS certificate verification is explicitly disabled.", "Keep certificate verification enabled; configure a trusted CA bundle instead.", "CWE-295"),
    HardeningRule("dede.hardening.python.ssl-cert-none", (".py",), r"\b(?:ssl\.)?(?:CERT_NONE|_create_unverified_context)\b", "Python SSL certificate verification is disabled.", "Use ssl.create_default_context() with certificate verification enabled.", "CWE-295"),
    HardeningRule("dede.hardening.javascript.tls-reject-unauthorized", (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"), r"\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", "Node.js TLS certificate verification is explicitly disabled.", "Do not disable rejectUnauthorized; trust the required CA explicitly.", "CWE-295"),
    HardeningRule("dede.hardening.java.hostname-verifier", (".java", ".kt", ".scala"), r"(?:HostnameVerifier|setHostnameVerifier|setDefaultHostnameVerifier)[^\n]*(?:->\s*true|return\s+true)", "Hostname verification accepts every host.", "Use the platform hostname verifier and validate the expected peer identity.", "CWE-295"),
    HardeningRule("dede.hardening.csharp.cert-validation", (".cs", ".csx"), r"DangerousAcceptAnyServerCertificateValidator|ServerCertificateCustomValidationCallback\s*=\s*[^;]*(?:=>\s*true|return\s+true)|ServerCertificateValidationCallback\s*\+?=\s*[^;]*(?:=>\s*true|return\s+true)", "TLS certificate validation accepts every certificate.", "Remove the permissive callback and use platform certificate validation.", "CWE-295"),
    HardeningRule("dede.hardening.go.insecure-skip-verify", (".go",), r"\bInsecureSkipVerify\s*:\s*true\b", "Go TLS verification is explicitly disabled.", "Keep InsecureSkipVerify false and configure RootCAs/ServerName correctly.", "CWE-295"),
    HardeningRule("dede.hardening.php.curl-no-verify", (".php",), r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b|CURLOPT_SSL_VERIFYHOST\s*,\s*0\b", "cURL TLS certificate/hostname verification is disabled.", "Enable CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST.", "CWE-295"),
    HardeningRule("dede.hardening.ruby.verify-none", (".rb",), r"OpenSSL::SSL::VERIFY_NONE|verify_mode\s*=\s*[^\n]*VERIFY_NONE", "Ruby TLS certificate verification is disabled.", "Use OpenSSL::SSL::VERIFY_PEER with a trusted certificate store.", "CWE-295"),
    # Crypto ----------------------------------------------------------------------
    HardeningRule("dede.hardening.python.ecb", (".py",), r"\bAES\.MODE_ECB\b|\bMODE_ECB\b", "ECB block-cipher mode is insecure for structured plaintext.", "Use an authenticated mode such as AES-GCM with a unique nonce.", "CWE-327"),
    HardeningRule("dede.hardening.java.ecb", (".java", ".kt", ".scala"), r"Cipher\.getInstance\s*\(\s*['\"][A-Za-z0-9_-]+/ECB(?:/|['\"])", "ECB block-cipher mode is explicitly selected.", "Use an authenticated cipher mode such as AES/GCM/NoPadding.", "CWE-327"),
    HardeningRule("dede.hardening.csharp.ecb", (".cs", ".csx"), r"\bCipherMode\.ECB\b|\.Mode\s*=\s*CipherMode\.ECB\b", "ECB block-cipher mode is explicitly selected.", "Use AES-GCM or another authenticated encryption mode.", "CWE-327"),
    HardeningRule("dede.hardening.javascript.ecb", (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"), r"createCipheriv\s*\(\s*['\"][^'\"]*ecb[^'\"]*['\"]", "ECB cipher mode is explicitly selected.", "Use an authenticated encryption construction such as AES-GCM.", "CWE-327"),
    HardeningRule("dede.hardening.go.des", (".go",), r"\bdes\.New(?:TripleDESCipher|Cipher)\s*\(", "DES/3DES is used for cryptographic protection.", "Use AES-GCM or ChaCha20-Poly1305.", "CWE-327", Severity.HIGH, Precision.HIGH),
    # Authentication/session -------------------------------------------------------
    HardeningRule("dede.hardening.python.jwt-no-verify", (".py",), r"jwt\.decode\s*\([^\n]*(?:verify\s*=\s*False|['\"]verify_signature['\"]\s*:\s*False)", "JWT signature verification is explicitly disabled.", "Always verify JWT signatures using an allowlisted algorithm and trusted key.", "CWE-347"),
    HardeningRule("dede.hardening.javascript.jwt-ignore-exp", (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"), r"jwt\.verify\s*\([^\n]*\bignoreExpiration\s*:\s*true\b", "JWT expiration verification is explicitly disabled.", "Enforce token expiration and validate issuer/audience where applicable.", "CWE-613"),
    HardeningRule("dede.hardening.csharp.jwt-no-lifetime", (".cs", ".csx"), r"\bValidateLifetime\s*=\s*false\b|\bRequireExpirationTime\s*=\s*false\b", "JWT lifetime validation is explicitly disabled.", "Require exp and validate token lifetime.", "CWE-613"),
    HardeningRule("dede.hardening.java-cookie-secure", (".java", ".kt", ".scala"), r"\.setSecure\s*\(\s*false\s*\)", "A cookie is explicitly configured without the Secure flag.", "Use Secure cookies for authentication/session state over HTTPS.", "CWE-614", Severity.MEDIUM, Precision.HIGH),
    HardeningRule("dede.hardening.java-cookie-httponly", (".java", ".kt", ".scala"), r"\.setHttpOnly\s*\(\s*false\s*\)", "A cookie is explicitly configured without HttpOnly.", "Keep HttpOnly enabled for session/authentication cookies.", "CWE-1004", Severity.MEDIUM, Precision.HIGH),
    HardeningRule("dede.hardening.javascript-cookie-secure", (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"), r"\bsecure\s*:\s*false\b[^\n]*(?:cookie|session)|(?:cookie|session)[^\n]*\bsecure\s*:\s*false\b", "Session/cookie configuration explicitly disables Secure.", "Enable Secure for session cookies in production.", "CWE-614", Severity.MEDIUM, Precision.HIGH),
    # Unsafe temporary files / permissions ----------------------------------------
    HardeningRule("dede.hardening.python-mktemp", (".py",), r"\btempfile\.mktemp\s*\(", "tempfile.mktemp() is vulnerable to race conditions.", "Use NamedTemporaryFile or mkstemp and keep the returned descriptor.", "CWE-377"),
    HardeningRule("dede.hardening.world-writable", (".py", ".js", ".ts", ".go", ".rb", ".php", ".c", ".cpp", ".cc", ".cxx"), r"\bchmod\s*\([^\n]*(?:0o?777|0777|0x1ff)\b|\bos\.Chmod\s*\([^\n]*0777\b", "A file/directory is made world-writable.", "Use the minimum required permissions and avoid world-writable application files.", "CWE-732", Severity.HIGH, Precision.HIGH),
    # CORS ------------------------------------------------------------------------
    HardeningRule("dede.hardening.cors-credentials-wildcard", (".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".cs"), r"(?:allow_origins|origins|allowedOrigins|WithOrigins)\s*[:=(][^\n]*['\"]\*['\"][^\n]*(?:allow_credentials|credentials|AllowCredentials)[^\n]*(?:true|True)|(?:allow_credentials|credentials|AllowCredentials)[^\n]*(?:true|True)[^\n]*(?:allow_origins|origins|allowedOrigins|WithOrigins)\s*[:=(][^\n]*['\"]\*['\"]", "Credentialed CORS is configured with a wildcard origin.", "Allow only explicit trusted origins when credentials are enabled.", "CWE-942", Severity.HIGH, Precision.HIGH),
)

_SECRET_NAME = re.compile(r"(?i)(?:pass(?:word|wd)?|secret|api[_-]?key|(?:access|refresh|reset)?[_-]?token|nonce|reset[_-]?code|auth(?:orization)?|session[_-]?id|cookie|private[_-]?key)")
_LOG_CALLS = {
    ".py": re.compile(r"\b(?:logging|logger|log)\.(?:debug|info|warning|error|critical|exception)\s*\("),
    ".js": re.compile(r"\b(?:console|logger|log)\.(?:log|debug|info|warn|error)\s*\("),
    ".jsx": re.compile(r"\b(?:console|logger|log)\.(?:log|debug|info|warn|error)\s*\("),
    ".ts": re.compile(r"\b(?:console|logger|log)\.(?:log|debug|info|warn|error)\s*\("),
    ".tsx": re.compile(r"\b(?:console|logger|log)\.(?:log|debug|info|warn|error)\s*\("),
    ".java": re.compile(r"\b(?:log|logger)\.(?:trace|debug|info|warn|error)\s*\("),
    ".kt": re.compile(r"\b(?:log|logger)\.(?:trace|debug|info|warn|error)\s*\("),
    ".cs": re.compile(r"\b(?:logger|_logger)\.(?:LogTrace|LogDebug|LogInformation|LogWarning|LogError|LogCritical)\s*\("),
    ".go": re.compile(r"\b(?:log|logger)\.(?:Print|Printf|Println|Debug|Info|Warn|Error)\s*\("),
    ".php": re.compile(r"\b(?:error_log|logger->(?:debug|info|warning|error))\s*\("),
    ".rb": re.compile(r"\b(?:logger|Rails\.logger)\.(?:debug|info|warn|error|fatal)\s*\("),
}
_RANDOM_APIS = {
    ".py": re.compile(r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits)\s*\("),
    ".js": re.compile(r"\bMath\.random\s*\("),
    ".ts": re.compile(r"\bMath\.random\s*\("),
    ".java": re.compile(r"\bnew\s+Random\s*\(|\bMath\.random\s*\("),
    ".kt": re.compile(r"\bRandom\.(?:next|Default)"),
    ".cs": re.compile(r"\bnew\s+Random\s*\("),
    ".go": re.compile(r"\bmath/rand\b|\brand\.(?:Int|Intn|Read|Uint)"),
    ".php": re.compile(r"\brand\s*\(|\bmt_rand\s*\("),
    ".rb": re.compile(r"\bKernel\.rand\s*\(|\brand\s*\("),
}


def _mask_strings(line: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', line)


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _finding(rule_id: str, file: str, line_no: int, line: str, message: str, recommendation: str, cwe: str, severity: Severity, *, precision: Precision = Precision.VERY_HIGH, kind: str = "hardening") -> Finding:
    confidence_score = 0.99 if precision == Precision.VERY_HIGH else 0.94
    return Finding(
        tool="dede-hardening",
        rule_id=rule_id,
        category=Category.SECURITY,
        severity=severity,
        confidence=Confidence.HIGH,
        confidence_score=confidence_score,
        precision=precision,
        cwe=[cwe],
        file=file,
        start_line=line_no,
        end_line=line_no,
        message=message,
        code_snippet=line.strip()[:400],
        recommendation=recommendation,
        normalized_type=kind,
        analysis_kind="hardening-static",
        engine_version="hardening-1.0",
        reachable=True,
        evidence=[Evidence(kind="configuration-fact", value=f"{file}:{line_no}", confidence=confidence_score)],
    )


class SecurityHardeningAnalyzer(Analyzer):
    name = "dede-hardening"

    def supports(self, project: ProjectContext) -> bool:
        supported = {ext for rule in _RULES for ext in rule.extensions} | set(_LOG_CALLS) | set(_RANDOM_APIS)
        return any(Path(item).suffix.lower() in supported for item in project.files)

    def version(self) -> str:
        return "1.0.0"

    def analyze(self, project: ProjectContext, config: AppConfig, raw_dir: Path) -> AnalyzerResult:
        started = time.monotonic()
        root = Path(project.root).resolve()
        findings: list[Finding] = []
        files_scanned = 0
        max_bytes = int(config.scan.max_file_size_mb * 1024 * 1024)
        for raw_path in project.files:
            path = Path(raw_path)
            ext = path.suffix.lower()
            relevant = any(ext in rule.extensions for rule in _RULES) or ext in _LOG_CALLS or ext in _RANDOM_APIS
            if not relevant:
                continue
            try:
                if path.stat().st_size > max_bytes:
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            files_scanned += 1
            file = _rel(path, root)
            for line_no, line in enumerate(lines, 1):
                for rule in _RULES:
                    if ext not in rule.extensions:
                        continue
                    candidate = _mask_strings(line) if rule.masked else line
                    if re.search(rule.regex, candidate, re.I):
                        findings.append(_finding(rule.id, file, line_no, line, rule.message, rule.recommendation, rule.cwe, rule.severity, precision=rule.precision, kind=rule.id.rsplit(".", 1)[-1]))
                masked = _mask_strings(line)
                log_call = _LOG_CALLS.get(ext)
                if log_call and log_call.search(masked) and _SECRET_NAME.search(masked):
                    findings.append(_finding(
                        "dede.hardening.sensitive-data.logging", file, line_no, line,
                        "A secret/credential-looking value is passed to a logging API.",
                        "Do not log credentials, tokens, session identifiers, private keys, or authorization headers.",
                        "CWE-532", Severity.HIGH, precision=Precision.HIGH, kind="sensitive-data-logging",
                    ))
                random_api = _RANDOM_APIS.get(ext)
                if random_api and random_api.search(masked):
                    lhs = masked.split("=", 1)[0] if "=" in masked else ""
                    if _SECRET_NAME.search(lhs):
                        findings.append(_finding(
                            "dede.hardening.security-token.insecure-random", file, line_no, line,
                            "A security-sensitive token/secret is generated with a non-cryptographic PRNG.",
                            "Use a cryptographically secure random generator (for example secrets/SystemRandom, crypto.randomBytes, SecureRandom, RandomNumberGenerator, crypto/rand).",
                            "CWE-338", Severity.HIGH, precision=Precision.HIGH, kind="insecure-random",
                        ))
        # Stable de-duplication inside this analyzer.
        unique: dict[tuple[str, str, int], Finding] = {}
        for finding in findings:
            unique.setdefault((finding.rule_id, finding.file, finding.start_line), finding)
        findings = list(unique.values())
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_path = raw_dir / "dede-hardening.json"
        raw_path.write_text(json.dumps({
            "engine": self.name,
            "version": self.version(),
            "files_scanned": files_scanned,
            "hits": len(findings),
            "rule_count": len(_RULES) + 2,
        }, indent=2), encoding="utf-8")
        return AnalyzerResult(
            tool=self.name,
            status=ToolStatus.SUCCESS,
            version=self.version(),
            message=f"{len(_RULES) + 2} precision hardening checks / {files_scanned} files ({len(findings)} hits)",
            findings=findings,
            raw_path=str(raw_path),
            duration_seconds=time.monotonic() - started,
            coverage={"files_scanned": files_scanned, "checks": len(_RULES) + 2},
        )
