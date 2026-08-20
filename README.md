# AWS Security Posture Automation

<h1>AWS Security Posture Automation — Automated Finding Enrichment and Reporting</h1>

<h2>Description</h2>

A Python automation tool using <b>boto3</b> that pulls findings from AWS Security Hub and GuardDuty, enriches them with asset context and threat intelligence, and generates structured security posture reports for both technical and executive audiences. Eliminates the manual effort of reviewing raw AWS findings by producing prioritised, enriched, actionable reports on a scheduled basis.

The tool maps every finding to <b>MITRE ATT&CK</b> techniques, correlates Security Hub findings with GuardDuty threat detections across the same assets, and produces a risk-prioritised remediation queue sorted by severity and asset criticality.

<br />

<h2>Problem This Solves</h2>

Raw AWS Security Hub and GuardDuty findings are:
- High volume — hundreds of findings per day in active environments
- Not correlated — Security Hub and GuardDuty findings for the same asset are not linked by default
- Not enriched — no asset context, no business criticality, no threat actor mapping
- Not prioritised — all HIGH findings look the same regardless of asset exposure
- Require manual reporting — no automated output for stakeholder communication

<br />

<h2>Languages and Utilities Used</h2>

- <b>Python 3.10+</b> — core automation
- <b>boto3</b> — AWS SDK for Security Hub and GuardDuty API calls
- <b>pandas</b> — finding aggregation and deduplication
- <b>jinja2</b> — HTML report templating
- <b>requests</b> — threat intelligence enrichment API calls
- <b>schedule</b> — automated daily execution

<h2>AWS Services Used</h2>

- <b>AWS Security Hub</b> — aggregated security findings
- <b>AWS GuardDuty</b> — threat detection findings
- <b>AWS IAM</b> — least-privilege role for read-only API access
- <b>AWS S3</b> — report storage and delivery
- <b>AWS Lambda</b> (optional) — serverless scheduled execution

<h2>Environments Used</h2>

- <b>AWS</b> — multi-account environment
- <b>Python 3.10+</b>
- <b>GitHub Actions</b> — scheduled pipeline execution

<br />

<h2>Architecture</h2>

```
AWS Security Hub API
        +
AWS GuardDuty API
        ↓
  boto3 Pull Layer
  - paginate all active findings
  - filter by severity threshold
  - deduplicate across sources
        ↓
  Enrichment Layer
  - asset criticality lookup (tag-based)
  - MITRE ATT&CK technique mapping
  - threat intelligence context
  - cross-source correlation
  (same asset in Security Hub + GuardDuty)
        ↓
  Prioritisation Engine
  - risk score = severity × asset criticality
  - CISA KEV check for CVE findings
  - internet-exposed asset flag
        ↓
  Report Generation
  - Executive summary (HTML)
  - Technical remediation queue (CSV)
  - MITRE ATT&CK coverage heatmap (JSON)
        ↓
  Delivery
  - S3 bucket upload
  - Optional: email via SES
```

<br />

<h2>Key Features</h2>

**Finding Correlation**
```python
# Correlate Security Hub and GuardDuty findings
# by resource ARN to surface high-confidence threats
def correlate_findings(sh_findings, gd_findings):
    correlated = []
    for sh in sh_findings:
        resource_arn = sh['Resources'][0]['Id']
        matching_gd = [
            gd for gd in gd_findings
            if resource_arn in gd['Resource']['InstanceDetails'].get('InstanceArn', '')
        ]
        if matching_gd:
            correlated.append({
                'resource': resource_arn,
                'security_hub': sh,
                'guardduty': matching_gd,
                'confidence': 'HIGH'  # Both sources agree
            })
    return correlated
```

**Risk Prioritisation**
```python
ASSET_CRITICALITY = {
    'internet-facing': 3,
    'data-store': 2,
    'internal': 1
}

SEVERITY_SCORE = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1
}

def risk_score(finding, asset_tags):
    criticality = ASSET_CRITICALITY.get(
        asset_tags.get('exposure', 'internal'), 1
    )
    severity = SEVERITY_SCORE.get(
        finding['Severity']['Label'], 1
    )
    return severity * criticality
```

**MITRE ATT&CK Mapping**
```python
GUARDDUTY_TO_ATTACK = {
    'UnauthorizedAccess:EC2/SSHBruteForce': 'T1110.001',
    'Recon:EC2/PortProbeUnprotectedPort':    'T1046',
    'CryptoCurrency:EC2/BitcoinTool.B':      'T1496',
    'Trojan:EC2/BlackholeTraffic':           'T1071',
    'UnauthorizedAccess:IAMUser/ConsoleLogin': 'T1078',
    'Policy:S3/BucketPublicAccessGranted':   'T1530',
}
```

<br />

<h2>Security Architecture</h2>

- **Read-only IAM role** — tool operates with minimum required permissions: `securityhub:GetFindings`, `guardduty:ListFindings`, `guardduty:GetFindings` only
- **No credentials in code** — IAM role assumed via instance profile or GitHub Actions OIDC
- **No finding data stored locally** — reports written directly to S3, not persisted on execution host
- **Audit logging** — every API call logged with timestamp and account ID
- **Multi-account support** — assumes cross-account roles via STS for consolidated reporting

<br />

<h2>Report Output</h2>

| Report | Audience | Format | Contents |
|--------|----------|--------|----------|
| Executive Summary | CISO / Leadership | HTML | Risk trend, top 5 findings, coverage metrics |
| Technical Queue | Security Engineering | CSV | All findings sorted by risk score, remediation steps |
| ATT&CK Heatmap | Detection Team | JSON (Navigator) | Technique coverage based on active findings |
| Correlation Report | IR Team | HTML | Assets appearing in both Security Hub and GuardDuty |

<br />

<h2>Repository Structure</h2>

```
aws-security-posture/
├── src/
│   ├── pull.py          # Security Hub + GuardDuty API calls
│   ├── enrich.py        # Asset context + TI enrichment
│   ├── correlate.py     # Cross-source finding correlation
│   ├── prioritise.py    # Risk scoring engine
│   ├── report.py        # Report generation
│   └── deliver.py       # S3 upload + notification
├── templates/
│   ├── executive.html   # Jinja2 executive report template
│   └── technical.html   # Jinja2 technical report template
├── config/
│   └── config.yaml      # Account IDs, severity thresholds
├── tests/
│   └── test_enrichment.py
├── .github/
│   └── workflows/
│       └── daily_run.yml
└── README.md
```

<br />

<h2>Author</h2>

**Praveena Mishra** — CISSP | Senior Security Engineer
[LinkedIn](https://linkedin.com/in/praveena-mishra)
