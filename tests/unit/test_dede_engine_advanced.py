"""Unit tests for the Dede native engine advanced rule sets (v0.5.0).

Tests cover detection and non-detection (safe counterexamples) for every
new rule introduced in:
  - advanced-python.json
  - advanced-javascript.json
  - advanced-java.json
  - advanced-go.json
  - advanced-secrets.json
  - advanced-infra.json
  - advanced-dotnet.json
  - advanced-languages.json
  - dotnet-flow.json
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dede.config import AppConfig
from dede.engine.analyzer import DedeEngineAnalyzer
from dede.engine.rules import load_rules_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules" / "dede-engine"


def _scan(tmp_path: Path, files: dict[str, str]) -> set[str]:
    """Write files, run engine, return set of triggered rule IDs."""
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    config = AppConfig()
    config.scan.exclude = []
    analyzer = DedeEngineAnalyzer(rules_dir=RULES_DIR)
    project_files = [str(tmp_path / name) for name in files]
    from dede.models import ProjectContext

    project = ProjectContext(root=str(tmp_path), files=project_files)
    raw_dir = tmp_path / ".raw"
    raw_dir.mkdir(exist_ok=True)
    result = analyzer.analyze(project, config, raw_dir)
    return {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# Schema integrity
# ---------------------------------------------------------------------------


class TestAdvancedRuleLoading:
    def test_all_advanced_files_load_without_error(self) -> None:
        files = load_rules_dir(RULES_DIR)
        assert files, "Rule files must exist"

    def test_rule_ids_unique_across_all_files(self) -> None:
        files = load_rules_dir(RULES_DIR)
        all_ids = [rule.id for f in files for rule in f.rules]
        assert len(all_ids) == len(set(all_ids)), "All rule IDs must be globally unique"

    def test_advanced_rule_files_present(self) -> None:
        expected = {
            "advanced-python.json",
            "advanced-javascript.json",
            "advanced-java.json",
            "advanced-go.json",
            "advanced-secrets.json",
            "advanced-infra.json",
            "advanced-platforms.json",
            "advanced-dotnet.json",
            "advanced-languages.json",
            "dotnet-flow.json",
        }
        found = {p.name for p in RULES_DIR.glob("*.json")}
        assert expected.issubset(found), f"Missing rule files: {expected - found}"

    def test_advanced_rules_have_required_metadata(self) -> None:
        files = load_rules_dir(RULES_DIR)
        advanced_rules = [
            rule for f in files for rule in f.rules if f.path.name.startswith("advanced-")
        ]
        assert advanced_rules, "No advanced rules found"
        for rule in advanced_rules:
            assert rule.cwe, f"{rule.id}: missing cwe"
            assert rule.owasp or rule.category in ("bug", "quality"), f"{rule.id}: missing owasp"
            assert rule.recommendation, f"{rule.id}: missing recommendation"
            assert rule.references, f"{rule.id}: missing references"

    def test_version_updated(self) -> None:
        version_file = RULES_DIR / "VERSION"
        assert version_file.exists(), "VERSION file must exist"
        version = version_file.read_text(encoding="utf-8").strip()
        assert version == "0.5.0", f"Expected 0.5.0, got {version}"


@pytest.mark.parametrize(
    "filename,source,rule_id",
    [
        ("unsafe.php", "<?php eval($_GET['code']);\n", "dede.php.execution.dynamic-eval"),
        ("unsafe.rb", "eval(params[:code])\n", "dede.ruby.execution.eval-params"),
        (
            "Unsafe.cs",
            'Process.Start(Request.Query["command"]);\n',
            "dede.dotnet.flow.command",
        ),
        ("unsafe.c", "gets(buffer);\n", "dede.c.memory.unbounded-gets"),
        ("unsafe.sh", 'eval "$payload"\n', "dede.shell.execution-eval-expansion"),
    ],
)
def test_platform_rules_detect_direct_dangerous_flows(
    tmp_path: Path, filename: str, source: str, rule_id: str
) -> None:
    assert rule_id in _scan(tmp_path, {filename: source})


def test_platform_rules_accept_safe_counterexamples(tmp_path: Path) -> None:
    ids = _scan(
        tmp_path,
        {
            "safe.php": "<?php $data = json_decode($payload, true);\n",
            "safe.rb": "YAML.safe_load(payload, permitted_classes: [])\n",
            "Safe.cs": 'cmd.Parameters.AddWithValue("@id", id);\n',
            "safe.c": "fgets(buffer, sizeof(buffer), stdin);\n",
            "safe.sh": 'printf "%s\\n" "$payload"\n',
        },
    )
    assert not any(
        rule_id.startswith(("dede.php.", "dede.ruby.", "dede.csharp.", "dede.c.", "dede.shell."))
        for rule_id in ids
    )


# ---------------------------------------------------------------------------
# Python advanced rules
# ---------------------------------------------------------------------------


class TestAdvancedPythonRules:
    def test_jwt_none_algorithm_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"auth.py": ("import jwt\n" "data = jwt.decode(token, key, algorithms=['none'])\n")},
        )
        assert "dede.py.auth.jwt-none-algorithm" in ids

    def test_jwt_no_verify_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "auth.py": (
                    "import jwt\n"
                    "payload = jwt.decode(token, options={'verify_signature': false})\n"
                )
            },
        )
        assert "dede.py.auth.jwt-no-verify" in ids

    def test_jwt_none_safe_with_hs256(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"auth.py": ("import jwt\n" "data = jwt.decode(token, key, algorithms=['HS256'])\n")},
        )
        assert "dede.py.auth.jwt-none-algorithm" not in ids

    def test_rsa_small_key_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "crypto.py": (
                    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                    "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
                )
            },
        )
        assert "dede.py.crypto.rsa-small-key" in ids

    def test_rsa_2048_safe(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "crypto.py": (
                    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                )
            },
        )
        assert "dede.py.crypto.rsa-small-key" not in ids

    def test_ecb_mode_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"enc.py": "cipher = Cipher(algorithms.AES(key), modes.ECB())\n"},
        )
        assert "dede.py.crypto.ecb-mode" in ids

    def test_ssti_render_string_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "views.py": (
                    "from flask import request, render_template_string\n"
                    "return render_template_string(request.args.get('t'))\n"
                )
            },
        )
        assert "dede.py.web.ssti-render-string" in ids

    def test_open_redirect_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "views.py": (
                    "from flask import request, redirect\n"
                    "return redirect(request.args.get('next'))\n"
                )
            },
        )
        assert "dede.py.web.open-redirect" in ids

    def test_open_redirect_safe_url_for(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "views.py": (
                    "from flask import url_for, redirect\n" "return redirect(url_for('home'))\n"
                )
            },
        )
        assert "dede.py.web.open-redirect" not in ids

    def test_ssrf_requests_user_url_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"api.py": ("import requests\n" "resp = requests.get(request.args.get('url'))\n")},
        )
        assert "dede.py.ssrf.requests-user-url" in ids

    def test_timing_attack_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"auth.py": "if stored_password == submitted_password:\n    login(user)\n"},
        )
        assert "dede.py.timing.str-compare-password" in ids

    def test_timing_attack_safe_compare_digest(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "auth.py": (
                    "import hmac\n"
                    "if hmac.compare_digest(stored_password, submitted_password):\n"
                    "    login(user)\n"
                )
            },
        )
        assert "dede.py.timing.str-compare-password" not in ids

    def test_cors_wildcard_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"app.py": "CORS(app, origins='*')\n"},
        )
        assert "dede.py.web.cors-wildcard" in ids

    def test_ldap_injection_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "ldap_auth.py": (
                    "import ldap3\n" "ldap3_conn.search(search_filter='(uid=' + username + ')')\n"
                )
            },
        )
        assert "dede.py.injection.ldap-unescaped" in ids

    def test_marshal_load_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"deser.py": "import marshal\nobj = marshal.loads(data)\n"},
        )
        assert "dede.py.deserialize.marshal-load" in ids

    def test_os_system_concat_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"cmd.py": "import os\nos.system('ls ' + user_dir)\n"},
        )
        assert "dede.py.cmd.os-system-concat" in ids

    def test_sql_raw_execute_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"db.py": ("cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n")},
        )
        assert "dede.py.web.sql-raw-execute" in ids

    def test_path_traversal_join_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "files.py": (
                    "import os\n" "path = os.path.join('/uploads', request.args.get('file'))\n"
                )
            },
        )
        assert "dede.py.path.traversal-join" in ids


# ---------------------------------------------------------------------------
# JavaScript / TypeScript advanced rules
# ---------------------------------------------------------------------------


class TestAdvancedJavaScriptRules:
    def test_prototype_pollution_bracket_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"app.js": 'obj["__proto__"]["isAdmin"] = true;\n'},
        )
        assert "dede.js.proto.pollution-bracket" in ids

    def test_settimeout_string_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"app.js": "setTimeout('doSomething()', 1000);\n"},
        )
        assert "dede.js.eval.settimeout-string" in ids

    def test_settimeout_function_safe(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"app.js": "setTimeout(() => doSomething(), 1000);\n"},
        )
        assert "dede.js.eval.settimeout-string" not in ids

    def test_cors_wildcard_reflected_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"server.js": ("res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n")},
        )
        assert "dede.js.cors.arbitrary-origin" in ids

    def test_jwt_none_algorithm_js_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"auth.js": "const payload = jwt.verify(token, secret, { algorithms: 'none' });\n"},
        )
        assert "dede.js.jwt.none-algorithm" in ids

    def test_path_traversal_join_js_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"files.js": ("const filePath = path.join('/uploads', req.query.file);\n")},
        )
        assert "dede.js.path.traversal-user-join" in ids

    def test_ssrf_fetch_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"proxy.js": ("const resp = await fetch(req.query.url);\n")},
        )
        assert "dede.js.ssrf.fetch-user-url" in ids

    def test_child_process_exec_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "shell.js": (
                    "const { exec } = require('child_process');\n" "exec('ls ' + req.query.dir);\n"
                )
            },
        )
        assert "dede.js.npm.child-process-user-input" in ids

    def test_sql_template_literal_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "db.js": (
                    "const userId = req.body.id;\n"
                    "const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);\n"
                )
            },
        )
        assert "dede.js.sql.template-literal-query" in ids

    def test_open_redirect_js_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"routes.js": ("res.redirect(req.query.next);\n")},
        )
        assert "dede.js.open-redirect" in ids

    def test_insecure_cookie_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"session.js": ("res.cookie('session', token, { httpOnly: false, secure: true });\n")},
        )
        assert "dede.js.session.insecure-cookie" in ids


# ---------------------------------------------------------------------------
# Java advanced rules
# ---------------------------------------------------------------------------


class TestAdvancedJavaRules:
    def test_jndi_lookup_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "Exploit.java": (
                    "import javax.naming.InitialContext;\n"
                    'ctx.lookup(request.getParameter("name"));\n'
                )
            },
        )
        assert "dede.java.jndi.lookup-user-input" in ids

    def test_spring_csrf_disabled_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"SecurityConfig.java": ("http.csrf().disable();\n")},
        )
        assert "dede.java.spring.csrf-disabled" in ids

    def test_spring_permitall_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "SecurityConfig.java": (
                    "http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());\n"
                )
            },
        )
        assert "dede.java.spring.permitall-all-requests" in ids

    def test_xxe_external_entity_enabled_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "XmlParser.java": (
                    'factory.setFeature("http://xml.org/sax/features/external-general-entities", true);\n'
                )
            },
        )
        assert "dede.java.xxe.external-entity-enabled" in ids

    def test_ssrf_url_user_input_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"Client.java": ('URL url = new URL(request.getParameter("target"));\n')},
        )
        assert "dede.java.ssrf.url-user-input" in ids

    def test_ognl_injection_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"Evaluator.java": ('Ognl.getValue(request.getParameter("expr"), context, root);\n')},
        )
        assert "dede.java.ognl.injection" in ids

    def test_des_cipher_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"Crypto.java": ('Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");\n')},
        )
        assert "dede.java.crypto.des-3des" in ids

    def test_aes_gcm_safe(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"Crypto.java": ('Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n')},
        )
        assert "dede.java.crypto.des-3des" not in ids

    def test_log_sensitive_data_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"Auth.java": ("logger.info('User password: ' + password);\n")},
        )
        assert "dede.java.log.sensitive-data-logging" in ids

    def test_jdbc_raw_concat_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"Dao.java": ('stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n')},
        )
        assert "dede.java.jdbc.raw-concat-query" in ids

    def test_runtime_exec_concat_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"Shell.java": ('Runtime.getRuntime().exec("ls " + userDir);\n')},
        )
        assert "dede.java.cmd.runtime-exec-concat" in ids

    def test_path_traversal_java_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"FileServer.java": ('File f = new File(request.getParameter("file"));\n')},
        )
        assert "dede.java.path.traversal-user-input" in ids


# ---------------------------------------------------------------------------
# Go advanced rules
# ---------------------------------------------------------------------------


class TestAdvancedGoRules:
    def test_http_timeout_not_set_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"client.go": ("package main\n" 'import "net/http"\n' "client := &http.Client{}\n")},
        )
        assert "dede.go.http.timeout-not-set" in ids

    def test_http_client_with_timeout_safe(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "client.go": (
                    "package main\n"
                    'import "net/http"\n'
                    "client := &http.Client{Timeout: 10 * time.Second}\n"
                )
            },
        )
        assert "dede.go.http.timeout-not-set" not in ids

    def test_default_client_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"fetch.go": ("package main\n" 'import "net/http"\n' "resp, err := http.Get(url)\n")},
        )
        assert "dede.go.http.default-client-usage" in ids

    def test_filepath_join_user_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "files.go": (
                    "package main\n"
                    'full := filepath.Join("/uploads", r.URL.Query().Get("name"))\n'
                )
            },
        )
        assert "dede.go.path.filepath-join-user" in ids

    def test_ssrf_go_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "proxy.go": (
                    "package main\n"
                    'req, _ := http.NewRequest("GET", r.URL.Query().Get("url"), nil)\n'
                )
            },
        )
        assert "dede.go.ssrf.http-request-user-url" in ids

    def test_tls_min_version_missing_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "tls.go": (
                    "package main\n"
                    'import "crypto/tls"\n'
                    "cfg := &tls.Config{InsecureSkipVerify: false}\n"
                )
            },
        )
        assert "dede.go.tls.min-version-not-set" in ids

    def test_tls_min_version_set_safe(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "tls.go": (
                    "package main\n"
                    'import "crypto/tls"\n'
                    "cfg := &tls.Config{MinVersion: tls.VersionTLS13}\n"
                )
            },
        )
        assert "dede.go.tls.min-version-not-set" not in ids

    def test_jwt_hardcoded_secret_go_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"auth.go": ("package main\n" 'token.SignedString([]byte("supersecret"))\n')},
        )
        assert "dede.go.jwt.hardcoded-secret" in ids

    def test_sql_sprintf_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "db.go": (
                    "package main\n"
                    'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)\n'
                )
            },
        )
        assert "dede.go.sql.fmt-sprintf-query" in ids

    def test_math_rand_security_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "token.go": (
                    "package main\n"
                    'import "math/rand"\n'
                    "// Generate session token\n"
                    "token := rand.Intn(1000000)\n"
                )
            },
        )
        assert "dede.go.crypto.rand-math" in ids

    def test_crypto_rand_safe(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "token.go": (
                    "package main\n"
                    'import "crypto/rand"\n'
                    "b := make([]byte, 32)\n"
                    "rand.Read(b)\n"
                )
            },
        )
        assert "dede.go.crypto.rand-math" not in ids


# ---------------------------------------------------------------------------
# Secrets advanced rules
# ---------------------------------------------------------------------------


class TestAdvancedSecretsRules:
    def test_jwt_literal_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "config.py": (
                    "JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
                    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'\n"
                )
            },
        )
        assert "dede.any.secrets.jwt-token-literal" in ids

    def test_gcp_service_account_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "sa.json": (
                    '{"type": "service_account", '
                    '"private_key_id": "abc123", '
                    '"private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIE..."}\n'
                )
            },
        )
        assert "dede.any.secrets.gcp-service-account-key" in ids

    def test_stripe_live_key_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"payments.py": "STRIPE_KEY = 'sk_live_abcdefghijklmnopqrstuvwxyz'\n"},
        )
        assert "dede.any.secrets.stripe-key" in ids

    def test_stripe_test_key_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"test_payments.py": "stripe.api_key = 'sk_test_abcdefghijklmnopqrstuvwx'\n"},
        )
        assert "dede.any.secrets.stripe-key" in ids

    def test_slack_bot_token_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"bot.py": "SLACK_TOKEN = 'xoxb-123456789012-123456789012-ABCDEFabcdefGHIJKLghijkl'\n"},
        )
        assert "dede.any.secrets.slack-token" in ids

    def test_github_token_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"deploy.sh": "GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDE\n"},
        )
        assert "dede.any.secrets.github-token" in ids

    def test_db_connection_string_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "settings.py": (
                    "DATABASE_URL = 'postgresql://admin:s3cretP4ssw0rd@prod-db.mycompany.com:5432/app'\n"
                )
            },
        )
        assert "dede.any.secrets.database-connection-string" in ids

    def test_db_connection_safe_env_var(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"settings.py": "DATABASE_URL = os.environ.get('DATABASE_URL')\n"},
        )
        assert "dede.any.secrets.database-connection-string" not in ids

    def test_npm_auth_token_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {".npmrc": "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz123456\n"},
        )
        assert "dede.any.secrets.npm-auth-token" in ids

    def test_ec_private_key_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "key.pem": "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...\n-----END EC PRIVATE KEY-----\n"
            },
        )
        assert "dede.any.secrets.private-key-ec" in ids

    def test_pkcs8_private_key_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "key.pem": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...\n-----END PRIVATE KEY-----\n"
            },
        )
        assert "dede.any.secrets.private-key-pkcs8" in ids

    def test_sendgrid_key_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "mail.py": (
                    "SG_API_KEY = 'SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS'\n"
                )
            },
        )
        assert "dede.any.secrets.sendgrid-api-key" in ids

    def test_azure_storage_key_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "storage.py": (
                    "CONN = 'AccountKey=dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXk=;'\n"
                )
            },
        )
        assert "dede.any.secrets.azure-storage-key" in ids


# ---------------------------------------------------------------------------
# Infrastructure advanced rules
# ---------------------------------------------------------------------------


class TestAdvancedInfraRules:
    def test_docker_add_instead_of_copy_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"Dockerfile": "FROM ubuntu:22.04\nADD ./app /app\nCMD ['python', 'app.py']\n"},
        )
        assert "dede.docker.add-instead-of-copy" in ids

    def test_k8s_latest_image_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "deploy.yaml": (
                    "apiVersion: apps/v1\n"
                    "kind: Deployment\n"
                    "spec:\n"
                    "  template:\n"
                    "    spec:\n"
                    "      containers:\n"
                    "        - name: app\n"
                    "          image: myapp:latest\n"
                )
            },
        )
        assert "dede.k8s.latest-image-tag" in ids

    def test_k8s_pinned_image_safe(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {"deploy.yaml": ("containers:\n" "  - name: app\n" "    image: myapp:1.2.3\n")},
        )
        assert "dede.k8s.latest-image-tag" not in ids

    def test_tf_s3_public_acl_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "main.tf": (
                    'resource "aws_s3_bucket" "public_data" {\n'
                    '  bucket = "my-public-bucket"\n'
                    '  acl    = "public-read"\n'
                    "}\n"
                )
            },
        )
        assert "dede.tf.s3-public-acl" in ids

    def test_tf_s3_private_acl_safe(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "main.tf": (
                    'resource "aws_s3_bucket" "private_data" {\n'
                    '  bucket = "my-private-bucket"\n'
                    '  acl    = "private"\n'
                    "}\n"
                )
            },
        )
        assert "dede.tf.s3-public-acl" not in ids

    def test_ci_workflow_write_all_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                ".github/workflows/ci.yml": (
                    "name: CI\n"
                    "permissions: write-all\n"
                    "jobs:\n"
                    "  build:\n"
                    "    runs-on: ubuntu-latest\n"
                )
            },
        )
        assert "dede.ci.workflow-write-all-permissions" in ids

    def test_k8s_allow_privilege_escalation_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "pod.yaml": (
                    "spec:\n"
                    "  containers:\n"
                    "  - name: app\n"
                    "    securityContext:\n"
                    "      runAsNonRoot: true\n"
                )
            },
        )
        assert "dede.k8s.allow-privilege-escalation" in ids

    def test_tf_encryption_disabled_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "rds.tf": (
                    'resource "aws_db_instance" "prod" {\n'
                    '  engine         = "mysql"\n'
                    '  instance_class = "db.t3.micro"\n'
                    "}\n"
                )
            },
        )
        assert "dede.tf.encryption-at-rest-disabled" in ids

    def test_k8s_automount_service_account_detected(self, tmp_path: Path) -> None:
        ids = _scan(
            tmp_path,
            {
                "pod.yaml": (
                    "apiVersion: v1\n"
                    "kind: Pod\n"
                    "metadata:\n"
                    "  name: myapp\n"
                    "spec:\n"
                    "  containers:\n"
                    "  - name: app\n"
                    "    image: myapp:1.0\n"
                )
            },
        )
        assert "dede.k8s.automount-service-account" in ids
