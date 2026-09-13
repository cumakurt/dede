# HTML and PDF reporting

Dede reports are designed to remain useful in air-gapped environments. The HTML report is a single self-contained document with no CDN, remote font, analytics, or JavaScript dependency. The PDF report is generated locally from the same evidence-backed template context.

## HTML report

`report.html` provides an offline dashboard with:

- sticky section navigation and active-section highlighting;
- light/dark themes stored only in the local browser;
- keyboard-accessible search (`/` focuses finding search);
- severity, category, analyzer, lifecycle, reachability and internet-exposure filters;
- expand/collapse controls and a live visible-finding counter;
- stable finding anchors and copyable permalinks;
- lifecycle, policy, attack-surface, analyzer-health, DedeQL and scan-performance dashboards;
- attack-path, source-to-sink dataflow and structured-evidence visualizations;
- responsive layouts and a print stylesheet.

All interactive behavior runs locally in the generated report. Source or finding data is not transmitted anywhere.

## PDF report

`report.pdf` is emitted as tagged **PDF/A-3u** for archival Unicode text and includes:

- A4 print layout with page headers, confidentiality marking and page numbering;
- page-numbered table of contents and PDF bookmarks;
- executive summary followed by technical evidence and appendix sections;
- lifecycle, policy, attack-surface and analyzer-health dashboards;
- evidence-backed finding detail with attack paths and dataflow;
- PDF document metadata (title, author, subject, generator and keywords);
- embedded `dede-report-evidence.json`, containing the canonical machine-readable scan payload;
- embedded `dede-scan-manifest.json`, containing source/ruleset/scanner traceability metadata;
- `report.pdf.sha256`, a SHA-256 sidecar for file-integrity verification.

The embedded evidence does not replace `report.json`; it makes a PDF artifact self-describing when it is archived or moved independently from the original report directory.

## Evidence discipline

Reporting derives reachability, exploitability, lifecycle, endpoint and policy claims only from fields produced by the analysis pipeline. Missing metadata remains unknown. Suggested remediation SLA targets in the report are explicitly guidance and are not presented as configured organizational policy.

## Report outputs

A normal scan can emit:

```text
report.json
report.html
report.pdf
report.pdf.sha256
report.sarif
metadata.json
scan-manifest.json
finding-lifecycle.json
```

The exact set depends on `reports.formats`.
