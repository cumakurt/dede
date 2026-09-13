# Security hardening and precision profiles

Dede 1.10 adds a deterministic hardening layer for security facts that do not need a full source-to-sink proof, such as TLS certificate verification being explicitly disabled or ECB mode being selected. These checks complement, rather than replace, semantic taint analysis.

## Profiles

`dede scan . --security-profile smart` is the default. The available profiles are:

- `strict`: VERY_HIGH findings plus independently corroborated HIGH findings.
- `smart`: precision-first production default; suppresses uncorroborated LOW native and EXPERIMENTAL findings.
- `audit`: includes LOW evidence for security review but still suppresses uncorroborated EXPERIMENTAL findings.
- `experimental`: exposes all findings, including business-logic and authorization candidates.

Experimental authorization/business-logic analysis is separately opt-in in `.dede.yml`; selecting the experimental profile does not silently enable an analyzer that the project disabled.

## Hardening families

The dedicated `dede-hardening` analyzer covers explicit certificate-verification bypasses, insecure block-cipher modes, JWT/session validation switches, unsafe temporary file/permission choices, credential-like data sent to logging APIs, insecure randomness used for security-token-looking values, and selected high-confidence platform-specific hardening failures.

Broader native rules that can be noisy are deliberately marked LOW/HIGH precision as appropriate and are filtered by the production profile unless another analyzer corroborates them.

## Precision laboratory

Run both deterministic regression corpora before promoting rules:

```bash
dede benchmark precision
dede benchmark hardening
```

The bundled corpora are regression suites, not claims about real-world false-positive rates. Organization-specific corpora should be added for internal frameworks and coding patterns.

## Experimental authorization and business logic

These checks are disabled by default:

```yaml
experimental:
  authorization_analysis: false
  business_logic_analysis: false
```

Enable them during security review or rule tuning. Findings are labelled `EXPERIMENTAL` and are not part of the default smart/audit output unless corroborated.
