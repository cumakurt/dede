# Policy and Suppression

Dede supports deterministic path-scoped release policies and expiring
suppressions in `.dede.yml`.

```yaml
suppress:
  entries:
    - rule: dede.example.rule
      path: tests/**
      reason: approved fixture
      expires: 2027-01-01
      approved_by: security-team

policy:
  enabled: true
  rules:
    - name: public-services
      path: services/public/**
      deny_severity: HIGH
      categories: [security, secret]
```

Expired suppressions stop matching automatically. Policy failures return the
normal security gate exit code and are recorded in scan metadata.
