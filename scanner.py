"""CloudLens scanner: finds risky settings in a cloud configuration snapshot.

Reads a simplified JSON snapshot (storage buckets, IAM users and policies,
security groups, root account) and flags common misconfigurations.
Standard library only (Python 3.8+).
"""

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass

SECTIONS = (
    "account",
    "storage_buckets",
    "iam_users",
    "iam_policies",
    "security_groups",
)

# Rule names (also used to build the recommendations list)
R_PUBLIC = "Public storage bucket"
R_UNENCRYPTED = "Unencrypted storage bucket"
R_ADMIN = "Full administrator policy"
R_WILDCARD = "Wildcard actions policy"
R_SERVICE = "Service-wide wildcard policy"
R_MFA = "User without MFA"
R_ROOT = "Root account without MFA"
R_KEY = "Old access key"
R_NETWORK = "Security group open to the internet"

WORLD_CIDRS = ("0.0.0.0/0", "::/0")
WEB_PORTS = (80, 443)
SENSITIVE_PORTS = {
    22: "SSH",
    445: "SMB",
    1433: "SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}
OLD_KEY_DAYS = 90
VERY_OLD_KEY_DAYS = 365

SEVERITY_POINTS = {"critical": 25, "high": 12, "medium": 5, "low": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2}

# Wildcard policy levels: severity -> (rule name, what it allows, how to fix)
POLICY_LEVELS = {
    "critical": (
        R_ADMIN,
        "Allows every action on every resource.",
        "Replace it with least-privilege permissions that list only the actions "
        "and resources the job needs.",
    ),
    "high": (
        R_WILDCARD,
        "Allows every action on the listed resources.",
        "List the specific actions that are needed instead of a wildcard (*).",
    ),
    "medium": (
        R_SERVICE,
        "Allows all actions of a whole service on every resource.",
        "Limit the actions to the ones needed and the resources to the ones used.",
    ),
}

RECOMMENDATIONS = (
    (
        (R_ROOT, R_MFA),
        "Require MFA for every console user, starting with the root account "
        "and administrators.",
    ),
    (
        (R_PUBLIC,),
        "Block public access on storage buckets unless one truly hosts a public website.",
    ),
    (
        (R_NETWORK,),
        "Close ports that are open to the whole internet, especially SSH, RDP "
        "and database ports.",
    ),
    (
        (R_ADMIN, R_WILDCARD, R_SERVICE),
        "Replace wildcard permissions with least-privilege policies that list "
        "only what each job needs.",
    ),
    ((R_KEY,), "Rotate access keys older than 90 days and delete keys nobody uses."),
    ((R_UNENCRYPTED,), "Turn on default encryption for all storage."),
)


@dataclass(frozen=True)
class Finding:  # pylint: disable=too-many-instance-attributes
    """One risky setting found in the snapshot."""

    severity: str
    rule: str
    category: str
    resource_type: str
    resource: str
    detail: str
    fix: str
    mitre_id: str = ""
    mitre_name: str = ""


def _items(snapshot, key):
    """Return (list of dict entries under `key`, number of malformed entries)."""
    value = snapshot.get(key)
    if value is None:
        return [], 0
    if not isinstance(value, list):
        return [], 1
    items = [item for item in value if isinstance(item, dict)]
    return items, len(value) - len(items)


def _name(item):
    """The display name of a resource."""
    name = item.get("name")
    return str(name) if name else "(unnamed)"


def _as_list(value):
    """Wrap a single value in a list and treat None as empty."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _to_int(value):
    """Convert to int, or None when that is not possible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _account_findings(account):
    """Root account without MFA."""
    if account.get("root_mfa_enabled") is not False:
        return []
    return [
        Finding(
            severity="critical",
            rule=R_ROOT,
            category="Identity",
            resource_type="Account",
            resource="Root account",
            detail="The all-powerful root account is protected by a password alone.",
            fix="Turn on MFA for the root account and stop using it for daily work.",
            mitre_id="T1078.004",
            mitre_name="Valid Accounts: Cloud Accounts",
        )
    ]


def _bucket_findings(buckets):
    """Public and unencrypted storage buckets."""
    findings = []
    for bucket in buckets:
        name = _name(bucket)
        if bucket.get("public_access") is True:
            findings.append(
                Finding(
                    severity="critical",
                    rule=R_PUBLIC,
                    category="Storage",
                    resource_type="Storage bucket",
                    resource=name,
                    detail="Anyone on the internet can read this bucket's contents.",
                    fix="Turn on 'block public access' and share files with "
                    "expiring signed links if needed.",
                    mitre_id="T1530",
                    mitre_name="Data from Cloud Storage",
                )
            )
        if bucket.get("encrypted") is False:
            findings.append(
                Finding(
                    severity="medium",
                    rule=R_UNENCRYPTED,
                    category="Storage",
                    resource_type="Storage bucket",
                    resource=name,
                    detail="Data in this bucket is stored without encryption at rest.",
                    fix="Enable default server-side encryption for the bucket.",
                )
            )
    return findings


def _texts(value):
    """A value (or a list of values) as a list of strings."""
    return [str(item) for item in _as_list(value)]


def _statement_level(statement):
    """How dangerous one policy statement is: critical, high, medium or None."""
    if str(statement.get("effect", "")).lower() != "allow":
        return None
    actions = _texts(statement.get("actions"))
    all_resources = "*" in _texts(statement.get("resources"))
    if any(action in ("*", "*:*") for action in actions):
        return "critical" if all_resources else "high"
    if all_resources and any(action.endswith(":*") for action in actions):
        return "medium"
    return None


def _policy_findings(policies, users_by_policy):
    """Policies that grant wildcard permissions."""
    findings = []
    for policy in policies:
        statements = [
            s for s in _as_list(policy.get("statements")) if isinstance(s, dict)
        ]
        levels = [_statement_level(statement) for statement in statements]
        levels = [level for level in levels if level]
        if not levels:
            continue
        level = min(levels, key=LEVEL_RANK.get)
        rule, what, fix = POLICY_LEVELS[level]
        name = _name(policy)
        holders = users_by_policy.get(name, [])
        if holders:
            detail = f"{what} Attached to: {', '.join(holders)}."
        else:
            detail = f"{what} Not attached to any user in this snapshot."
        findings.append(
            Finding(
                severity=level,
                rule=rule,
                category="Identity",
                resource_type="IAM policy",
                resource=name,
                detail=detail,
                fix=fix,
                mitre_id="T1078.004",
                mitre_name="Valid Accounts: Cloud Accounts",
            )
        )
    return findings


def _user_finding(name, severity, rule, detail, fix):
    """A Finding about an IAM user (shared by the user rules)."""
    return Finding(
        severity=severity,
        rule=rule,
        category="Identity",
        resource_type="IAM user",
        resource=name,
        detail=detail,
        fix=fix,
        mitre_id="T1078.004",
        mitre_name="Valid Accounts: Cloud Accounts",
    )


def _mfa_finding(user, name, is_admin):
    """Console user without MFA (critical when the user is an administrator)."""
    if user.get("console_access") is not True or user.get("mfa_enabled") is not False:
        return None
    detail = "This user can sign in to the console with only a password"
    detail += " and holds a full administrator policy." if is_admin else "."
    return _user_finding(
        name,
        "critical" if is_admin else "high",
        R_MFA,
        detail,
        "Require an MFA device for this user.",
    )


def _key_finding(user, name):
    """Access key older than the allowed age."""
    age = _to_int(user.get("access_key_age_days"))
    if age is None or age <= OLD_KEY_DAYS:
        return None
    return _user_finding(
        name,
        "high" if age > VERY_OLD_KEY_DAYS else "medium",
        R_KEY,
        f"The access key is {age} days old (limit: {OLD_KEY_DAYS}).",
        "Create a new key, update whatever uses it, then delete the old one.",
    )


def _user_findings(users, admin_policies):
    """Console users without MFA and old access keys."""
    findings = []
    for user in users:
        name = _name(user)
        held = _texts(user.get("policies"))
        is_admin = any(policy in admin_policies for policy in held)
        for finding in (_mfa_finding(user, name, is_admin), _key_finding(user, name)):
            if finding:
                findings.append(finding)
    return findings


def _port_range(rule):
    """(start, end) ports of an ingress rule, or None when they are not numbers."""
    start = _to_int(rule.get("port_from"))
    end = _to_int(rule.get("port_to"))
    if start is None or end is None:
        return None
    return (start, end) if start <= end else (end, start)


def _world_open_finding(group_name, start, end):
    """A Finding for a rule open to the whole internet on ports start..end, or None."""
    common = {
        "category": "Network",
        "resource_type": "Security group",
        "resource": group_name,
        "rule": R_NETWORK,
    }
    if start <= 0 and end >= 65535:
        return Finding(
            severity="critical",
            detail="Every port is open to the whole internet.",
            fix="Remove this rule and allow only the specific ports that are needed, "
            "from known addresses.",
            mitre_id="T1190",
            mitre_name="Exploit Public-Facing Application",
            **common,
        )
    exposed = sorted(port for port in SENSITIVE_PORTS if start <= port <= end)
    if exposed:
        labels = ", ".join(f"{port} ({SENSITIVE_PORTS[port]})" for port in exposed)
        return Finding(
            severity="critical",
            detail=f"Port {labels} is open to the whole internet.",
            fix="Restrict these ports to your office or VPN address range, "
            "or use a bastion host.",
            mitre_id="T1133",
            mitre_name="External Remote Services",
            **common,
        )
    if start == end and start in WEB_PORTS:
        return None
    ports = f"Port {start}" if start == end else f"Ports {start}-{end}"
    return Finding(
        severity="high",
        detail=f"{ports} is open to the whole internet.",
        fix="Only ports 80 and 443 should be open to everyone. "
        "Restrict this one to known addresses.",
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        **common,
    )


def _security_group_findings(groups):
    """Security group rules open to the internet. Returns (findings, skipped)."""
    findings = []
    skipped = 0
    for group in groups:
        name = _name(group)
        for rule in _as_list(group.get("ingress")):
            if not isinstance(rule, dict):
                skipped += 1
                continue
            if str(rule.get("cidr", "")) not in WORLD_CIDRS:
                continue
            ports = _port_range(rule)
            if ports is None:
                skipped += 1
                continue
            finding = _world_open_finding(name, *ports)
            if finding:
                findings.append(finding)
    return findings, skipped


def _risk_level(score, has_resources):
    """Turn a 0-100 score into a label."""
    if not has_resources:
        return "No data"
    if score >= 70:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 15:
        return "Elevated"
    return "Low"


def _risky_resources(findings):
    """The resources with the most risk points, worst first."""
    totals = {}
    for finding in findings:
        entry = totals.setdefault(
            (finding.resource_type, finding.resource),
            {
                "resource": finding.resource,
                "type": finding.resource_type,
                "findings": 0,
                "points": 0,
            },
        )
        entry["findings"] += 1
        entry["points"] += SEVERITY_POINTS[finding.severity]
    ranked = sorted(totals.values(), key=lambda e: (-e["points"], e["resource"]))
    return ranked[:8]


def _recommendations(findings):
    """Build the 'next steps' list from the rules that fired."""
    fired = {finding.rule for finding in findings}
    recs = [text for rules, text in RECOMMENDATIONS if fired & set(rules)]
    if not recs:
        recs.append(
            "No risky settings found. Re-scan after every configuration change."
        )
    return recs


def _read_sections(snapshot):
    """Split a snapshot into its sections. Returns (sections, account, skipped)."""
    sections = {}
    skipped = 0
    for key in SECTIONS[1:]:
        sections[key], bad = _items(snapshot, key)
        skipped += bad
    account = snapshot.get("account")
    if "account" in snapshot and not isinstance(account, dict):
        skipped += 1
    return sections, account if isinstance(account, dict) else {}, skipped


def _users_by_policy(users):
    """Map each policy name to the names of the users who hold it."""
    holders = defaultdict(list)
    for user in users:
        for policy_name in _texts(user.get("policies")):
            holders[policy_name].append(_name(user))
    return holders


def _build_report(findings, resources, skipped):
    """Turn the sorted findings into the JSON report."""
    score = min(100, sum(SEVERITY_POINTS[f.severity] for f in findings))
    by_severity = Counter(f.severity for f in findings)
    by_category = Counter(f.category for f in findings)
    return {
        "summary": {
            "resources": resources,
            "findings": len(findings),
            "skipped": skipped,
            "risk_score": score,
            "risk_level": _risk_level(score, resources > 0),
        },
        "by_severity": {sev: by_severity.get(sev, 0) for sev in SEVERITY_ORDER},
        "by_category": [
            {"category": name, "count": count}
            for name, count in sorted(
                by_category.items(), key=lambda kv: (-kv[1], kv[0])
            )
        ],
        "findings": [asdict(finding) for finding in findings],
        "risky_resources": _risky_resources(findings),
        "recommendations": _recommendations(findings),
    }


def scan(snapshot):
    """Scan a parsed snapshot (a dict) and return a JSON-serializable report."""
    sections, account, skipped = _read_sections(snapshot)
    policy_findings = _policy_findings(
        sections["iam_policies"], _users_by_policy(sections["iam_users"])
    )
    admin_policies = {f.resource for f in policy_findings if f.rule == R_ADMIN}
    network_findings, bad_rules = _security_group_findings(sections["security_groups"])

    findings = (
        _account_findings(account)
        + _bucket_findings(sections["storage_buckets"])
        + policy_findings
        + _user_findings(sections["iam_users"], admin_policies)
        + network_findings
    )
    findings.sort(
        key=lambda f: (SEVERITY_ORDER[f.severity], f.resource_type, f.resource, f.rule)
    )
    resources = sum(len(items) for items in sections.values()) + (1 if account else 0)
    return _build_report(findings, resources, skipped + bad_rules)


def analyze_text(text):
    """Parse JSON text and scan it. Raises ValueError with a friendly message."""
    try:
        snapshot = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"That is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}."
        ) from exc
    except RecursionError as exc:
        raise ValueError("That JSON is nested too deeply.") from exc
    if not isinstance(snapshot, dict):
        raise ValueError(
            "The snapshot must be a JSON object with sections such as storage_buckets."
        )
    if not any(key in snapshot for key in SECTIONS):
        raise ValueError(
            "No known sections found. Expected at least one of: "
            + ", ".join(SECTIONS)
            + "."
        )
    return scan(snapshot)


def sample_snapshot():
    """A deliberately insecure demo environment with a few safe resources mixed in."""
    return {
        "account": {"root_mfa_enabled": False},
        "storage_buckets": [
            {"name": "company-backups", "public_access": True, "encrypted": False},
            {"name": "hr-documents", "public_access": False, "encrypted": True},
            {"name": "website-assets", "public_access": True, "encrypted": True},
            {"name": "app-logs", "public_access": False, "encrypted": False},
        ],
        "iam_users": [
            {
                "name": "alice",
                "console_access": True,
                "mfa_enabled": True,
                "access_key_age_days": 30,
                "policies": ["ReadOnly"],
            },
            {
                "name": "bob",
                "console_access": True,
                "mfa_enabled": False,
                "access_key_age_days": 210,
                "policies": ["AdminAccess"],
            },
            {
                "name": "carol",
                "console_access": True,
                "mfa_enabled": False,
                "access_key_age_days": 400,
                "policies": ["ReadOnly"],
            },
            {
                "name": "ci-bot",
                "console_access": False,
                "access_key_age_days": 120,
                "policies": ["DeployPolicy"],
            },
        ],
        "iam_policies": [
            {
                "name": "AdminAccess",
                "statements": [
                    {"effect": "Allow", "actions": ["*"], "resources": ["*"]}
                ],
            },
            {
                "name": "ReadOnly",
                "statements": [
                    {
                        "effect": "Allow",
                        "actions": ["s3:GetObject", "s3:ListBucket"],
                        "resources": ["arn:aws:s3:::hr-documents/*"],
                    }
                ],
            },
            {
                "name": "DeployPolicy",
                "statements": [
                    {"effect": "Allow", "actions": ["ec2:*"], "resources": ["*"]}
                ],
            },
        ],
        "security_groups": [
            {
                "name": "web-sg",
                "ingress": [
                    {"port_from": 80, "port_to": 80, "cidr": "0.0.0.0/0"},
                    {"port_from": 443, "port_to": 443, "cidr": "0.0.0.0/0"},
                ],
            },
            {
                "name": "admin-sg",
                "ingress": [{"port_from": 22, "port_to": 22, "cidr": "0.0.0.0/0"}],
            },
            {
                "name": "db-sg",
                "ingress": [{"port_from": 3306, "port_to": 3306, "cidr": "0.0.0.0/0"}],
            },
            {
                "name": "dev-sg",
                "ingress": [{"port_from": 0, "port_to": 65535, "cidr": "0.0.0.0/0"}],
            },
            {
                "name": "app-sg",
                "ingress": [
                    {"port_from": 8080, "port_to": 8080, "cidr": "0.0.0.0/0"},
                    {"port_from": 5432, "port_to": 5432, "cidr": "10.0.0.0/16"},
                ],
            },
        ],
    }


def generate_sample():
    """The demo snapshot as pretty-printed JSON text."""
    return json.dumps(sample_snapshot(), indent=2) + "\n"
