# Security policy

## Supported versions

Only the latest release on the default branch is supported with security
fixes. Scanner rule updates may be released independently; the native ruleset
version is recorded in every report.

## Reporting a vulnerability

Do not open a public issue for a vulnerability in Dede, its Docker image, or
the release workflow. Contact the maintainers privately through the security
contact at **cumakurt@gmail.com** and include a minimal reproduction,
affected version, impact, and a safe disclosure timeline. Do not include real
credentials or customer source code; redact them before sending evidence.

Confirmed issues are tracked privately while a fix or mitigation is prepared.
Release notes document published security fixes.

## Scanner limitations

Dede is a static analysis tool. A finding is evidence for review, not proof of
exploitability. Native .NET flow is bounded local lexical analysis and does not
replace Roslyn compilation, runtime testing, dependency vulnerability analysis,
or an authorization review. Reports marked incomplete coverage must be treated
as incomplete.
