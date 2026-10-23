"""Automated tests for CloudLens (run with: python -m unittest -v)."""

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from app import Handler
from scanner import (
    R_ADMIN,
    R_KEY,
    R_MFA,
    R_NETWORK,
    R_PUBLIC,
    R_ROOT,
    R_SERVICE,
    R_UNENCRYPTED,
    R_WILDCARD,
    analyze_text,
    generate_sample,
    scan,
)


def findings_for(report, rule=None, resource=None):
    """Return the findings of one rule and/or one resource."""
    return [
        f
        for f in report["findings"]
        if (rule is None or f["rule"] == rule)
        and (resource is None or f["resource"] == resource)
    ]


def sg(*rules):
    """A snapshot with one security group that has the given ingress rules."""
    return {"security_groups": [{"name": "g", "ingress": list(rules)}]}


def world(port_from, port_to=None, cidr="0.0.0.0/0"):
    """One ingress rule from `cidr` on a port or port range."""
    return {
        "port_from": port_from,
        "port_to": port_from if port_to is None else port_to,
        "cidr": cidr,
    }


def user(**fields):
    """A snapshot with one IAM user."""
    return {"iam_users": [{"name": "u", **fields}]}


class BucketRuleTests(unittest.TestCase):
    """Checks the storage bucket rules."""

    def test_public_bucket_is_critical(self):
        """A public bucket is a critical finding."""
        report = scan({"storage_buckets": [{"name": "b", "public_access": True}]})
        found = findings_for(report, R_PUBLIC)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "critical")
        self.assertEqual(found[0]["mitre_id"], "T1530")

    def test_private_bucket_is_fine(self):
        """A private, encrypted bucket raises nothing."""
        report = scan(
            {
                "storage_buckets": [
                    {"name": "b", "public_access": False, "encrypted": True}
                ]
            }
        )
        self.assertEqual(report["findings"], [])

    def test_unencrypted_bucket_is_medium(self):
        """encrypted: false is a medium finding."""
        report = scan({"storage_buckets": [{"name": "b", "encrypted": False}]})
        found = findings_for(report, R_UNENCRYPTED)
        self.assertEqual([f["severity"] for f in found], ["medium"])

    def test_missing_fields_are_not_guessed(self):
        """A bucket with no public_access or encrypted fields raises nothing."""
        self.assertEqual(scan({"storage_buckets": [{"name": "b"}]})["findings"], [])


class PolicyRuleTests(unittest.TestCase):
    """Checks the IAM policy rules."""

    @staticmethod
    def policy(actions, resources, effect="Allow"):
        """A snapshot with one policy that has one statement."""
        statement = {"effect": effect, "actions": actions, "resources": resources}
        return {"iam_policies": [{"name": "p", "statements": [statement]}]}

    def test_full_admin_is_critical(self):
        """Allow * on * is a critical full administrator policy."""
        report = scan(self.policy(["*"], ["*"]))
        self.assertEqual(
            [f["severity"] for f in findings_for(report, R_ADMIN)], ["critical"]
        )

    def test_action_wildcard_is_high(self):
        """Allow * on named resources is high."""
        report = scan(self.policy(["*"], ["arn:one"]))
        self.assertEqual(
            [f["severity"] for f in findings_for(report, R_WILDCARD)], ["high"]
        )

    def test_service_wildcard_is_medium(self):
        """Allow ec2:* on * is medium."""
        report = scan(self.policy(["ec2:*"], ["*"]))
        self.assertEqual(
            [f["severity"] for f in findings_for(report, R_SERVICE)], ["medium"]
        )

    def test_specific_permissions_are_fine(self):
        """Specific actions on specific resources raise nothing."""
        report = scan(self.policy(["s3:GetObject"], ["arn:one"]))
        self.assertEqual(report["findings"], [])

    def test_deny_statement_is_ignored(self):
        """A Deny statement never counts as risky."""
        self.assertEqual(scan(self.policy(["*"], ["*"], effect="Deny"))["findings"], [])

    def test_single_string_values_work(self):
        """Action and resource may be plain strings instead of lists."""
        report = scan(self.policy("*", "*"))
        self.assertEqual(len(findings_for(report, R_ADMIN)), 1)

    def test_worst_statement_wins(self):
        """A policy with several risky statements is reported once, at the worst level."""
        statements = [
            {"effect": "Allow", "actions": ["ec2:*"], "resources": ["*"]},
            {"effect": "Allow", "actions": ["*"], "resources": ["*"]},
        ]
        report = scan({"iam_policies": [{"name": "p", "statements": statements}]})
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["severity"], "critical")

    def test_attached_users_are_listed(self):
        """The finding names the users who hold the policy."""
        snapshot = self.policy(["*"], ["*"])
        snapshot["iam_users"] = [{"name": "zed", "policies": ["p"]}]
        found = findings_for(scan(snapshot), R_ADMIN)
        self.assertIn("zed", found[0]["detail"])


class UserRuleTests(unittest.TestCase):
    """Checks the IAM user rules."""

    def test_console_user_without_mfa_is_high(self):
        """Console access with MFA off is a high finding."""
        report = scan(user(console_access=True, mfa_enabled=False))
        self.assertEqual([f["severity"] for f in findings_for(report, R_MFA)], ["high"])

    def test_admin_without_mfa_is_critical(self):
        """The same user holding an admin policy is critical."""
        snapshot = user(console_access=True, mfa_enabled=False, policies=["root-like"])
        snapshot["iam_policies"] = [
            {
                "name": "root-like",
                "statements": [
                    {"effect": "Allow", "actions": ["*"], "resources": ["*"]}
                ],
            }
        ]
        found = findings_for(scan(snapshot), R_MFA)
        self.assertEqual(found[0]["severity"], "critical")

    def test_no_console_access_needs_no_mfa(self):
        """A service account without console access is not flagged for MFA."""
        report = scan(user(console_access=False, mfa_enabled=False))
        self.assertEqual(findings_for(report, R_MFA), [])

    def test_mfa_enabled_is_fine(self):
        """A console user with MFA on raises nothing."""
        self.assertEqual(
            scan(user(console_access=True, mfa_enabled=True))["findings"], []
        )

    def test_key_age_boundaries(self):
        """90 days is fine, 91 is medium, 365 is medium, 366 is high."""
        expected = {90: None, 91: "medium", 365: "medium", 366: "high"}
        for age, severity in expected.items():
            with self.subTest(age=age):
                found = findings_for(scan(user(access_key_age_days=age)), R_KEY)
                self.assertEqual(
                    [f["severity"] for f in found], [severity] if severity else []
                )

    def test_bad_key_age_is_ignored(self):
        """A key age that is not a number raises nothing and does not crash."""
        self.assertEqual(scan(user(access_key_age_days="abc"))["findings"], [])


class AccountRuleTests(unittest.TestCase):
    """Checks the root account rule."""

    def test_root_without_mfa_is_critical(self):
        """root_mfa_enabled: false is critical."""
        found = findings_for(scan({"account": {"root_mfa_enabled": False}}), R_ROOT)
        self.assertEqual([f["severity"] for f in found], ["critical"])

    def test_root_with_mfa_is_fine(self):
        """root_mfa_enabled: true raises nothing."""
        self.assertEqual(scan({"account": {"root_mfa_enabled": True}})["findings"], [])

    def test_unknown_root_status_is_not_guessed(self):
        """A missing root_mfa_enabled field raises nothing."""
        self.assertEqual(scan({"account": {}})["findings"], [])


class SecurityGroupRuleTests(unittest.TestCase):
    """Checks the firewall (security group) rules."""

    def severities(self, snapshot):
        """The severities of all network findings in a snapshot."""
        return [f["severity"] for f in findings_for(scan(snapshot), R_NETWORK)]

    def test_ssh_open_to_world_is_critical(self):
        """Port 22 open to 0.0.0.0/0 is critical."""
        self.assertEqual(self.severities(sg(world(22))), ["critical"])

    def test_database_port_is_critical(self):
        """Port 3306 open to the world is critical."""
        self.assertEqual(self.severities(sg(world(3306))), ["critical"])

    def test_all_ports_is_critical(self):
        """Ports 0-65535 open to the world is critical."""
        self.assertEqual(self.severities(sg(world(0, 65535))), ["critical"])

    def test_range_containing_ssh_is_critical(self):
        """A range like 20-25 includes SSH and is critical."""
        self.assertEqual(self.severities(sg(world(20, 25))), ["critical"])

    def test_reversed_range_is_handled(self):
        """A range written backwards still works."""
        self.assertEqual(self.severities(sg(world(25, 20))), ["critical"])

    def test_other_port_is_high(self):
        """Port 8080 open to the world is high."""
        self.assertEqual(self.severities(sg(world(8080))), ["high"])

    def test_web_ports_are_fine(self):
        """Ports 80 and 443 open to the world are normal."""
        self.assertEqual(self.severities(sg(world(80), world(443))), [])

    def test_private_range_is_fine(self):
        """Port 22 open only to a private range raises nothing."""
        self.assertEqual(self.severities(sg(world(22, cidr="10.0.0.0/16"))), [])

    def test_ipv6_world_is_caught(self):
        """::/0 counts as the whole internet."""
        self.assertEqual(self.severities(sg(world(22, cidr="::/0"))), ["critical"])

    def test_invalid_ports_are_skipped_and_counted(self):
        """A world-open rule with non-numeric ports is skipped, not guessed."""
        report = scan(sg({"port_from": "x", "port_to": "y", "cidr": "0.0.0.0/0"}))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["skipped"], 1)


class InputHandlingTests(unittest.TestCase):
    """Checks broken, odd or hostile input."""

    def test_invalid_json_gives_a_helpful_message(self):
        """Broken JSON raises ValueError that names the line."""
        with self.assertRaises(ValueError) as ctx:
            analyze_text('{"storage_buckets": [}')
        self.assertIn("not valid JSON", str(ctx.exception))
        self.assertIn("line 1", str(ctx.exception))

    def test_non_object_is_rejected(self):
        """A JSON list at the top level is rejected."""
        with self.assertRaises(ValueError):
            analyze_text("[1, 2, 3]")

    def test_unknown_sections_are_rejected(self):
        """An object with none of the known sections is rejected."""
        with self.assertRaises(ValueError) as ctx:
            analyze_text('{"hello": "world"}')
        self.assertIn("No known sections", str(ctx.exception))

    def test_empty_text_is_rejected(self):
        """Empty text is invalid JSON."""
        with self.assertRaises(ValueError):
            analyze_text("")

    def test_deeply_nested_json_is_rejected(self):
        """Absurdly nested JSON gives a clean error, not a crash."""
        with self.assertRaises(ValueError):
            analyze_text("[" * 100000)

    def test_wrong_types_do_not_crash(self):
        """Sections or entries of the wrong type are skipped and counted."""
        report = scan(
            {
                "storage_buckets": "oops",
                "iam_users": [1, "two", None, {"name": "ok"}],
                "iam_policies": {"a": 1},
                "account": "x",
                "security_groups": [{"name": "g", "ingress": ["bad", 5]}],
            }
        )
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["skipped"], 1 + 3 + 1 + 1 + 2)

    def test_unnamed_and_unicode_names(self):
        """Missing names show as (unnamed) and unicode names survive."""
        report = scan(
            {
                "storage_buckets": [
                    {"public_access": True},
                    {"name": "données-été", "public_access": True},
                ]
            }
        )
        names = sorted(f["resource"] for f in report["findings"])
        self.assertEqual(names, ["(unnamed)", "données-été"])

    def test_empty_sections_mean_no_data(self):
        """Known but empty sections give a 'No data' report."""
        report = analyze_text('{"storage_buckets": []}')
        self.assertEqual(report["summary"]["risk_level"], "No data")

    def test_clean_config_is_low_risk(self):
        """A safe configuration scores 0 and gets the all-clear message."""
        report = scan(
            {
                "account": {"root_mfa_enabled": True},
                "storage_buckets": [
                    {"name": "b", "public_access": False, "encrypted": True}
                ],
            }
        )
        self.assertEqual(report["summary"]["risk_score"], 0)
        self.assertEqual(report["summary"]["risk_level"], "Low")
        self.assertIn("No risky settings", report["recommendations"][0])


class SampleReportTests(unittest.TestCase):
    """Checks the built-in demo environment."""

    def setUp(self):
        """Scan the sample once per test."""
        self.report = analyze_text(generate_sample())

    def test_headline_numbers(self):
        """The demo has 17 resources and 16 findings, rated Critical."""
        summary = self.report["summary"]
        self.assertEqual(summary["resources"], 17)
        self.assertEqual(summary["findings"], 16)
        self.assertEqual(summary["risk_level"], "Critical")
        self.assertEqual(summary["risk_score"], 100)

    def test_severity_counts_add_up(self):
        """Counts by severity and by area both add up to the total."""
        total = self.report["summary"]["findings"]
        self.assertEqual(sum(self.report["by_severity"].values()), total)
        self.assertEqual(sum(c["count"] for c in self.report["by_category"]), total)
        self.assertEqual(self.report["by_severity"]["critical"], 8)

    def test_findings_are_sorted_worst_first(self):
        """Critical findings come before high, medium and low."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranks = [order[f["severity"]] for f in self.report["findings"]]
        self.assertEqual(ranks, sorted(ranks))

    def test_admin_user_without_mfa_is_critical(self):
        """bob holds AdminAccess and has no MFA, so his finding is critical."""
        found = findings_for(self.report, R_MFA, "bob")
        self.assertEqual(found[0]["severity"], "critical")

    def test_safe_resources_are_not_flagged(self):
        """The private encrypted bucket, the web group and alice are clean."""
        for resource in ("hr-documents", "web-sg", "alice", "ReadOnly"):
            with self.subTest(resource=resource):
                self.assertEqual(findings_for(self.report, resource=resource), [])

    def test_riskiest_resources_are_ranked(self):
        """Riskiest resources are sorted by points, highest first."""
        points = [r["points"] for r in self.report["risky_resources"]]
        self.assertEqual(points, sorted(points, reverse=True))

    def test_recommendations_exist(self):
        """The sample triggers all six recommendation groups."""
        self.assertEqual(len(self.report["recommendations"]), 6)

    def test_sample_is_deterministic_and_json_safe(self):
        """The sample is identical every time and the report can be sent as JSON."""
        self.assertEqual(generate_sample(), generate_sample())
        json.dumps(self.report)


class ServerTests(unittest.TestCase):
    """Starts the real server on a free port and calls it."""

    @classmethod
    def setUpClass(cls):
        """Start the server in a background thread."""
        cls.server = ThreadingHTTPServer(  # pylint: disable=consider-using-with
            ("127.0.0.1", 0), Handler
        )
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        """Stop the server."""
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None):
        """Call the test server and return (status code, response bytes)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_index_served(self):
        """The dashboard page loads."""
        status, data = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"CloudLens", data)

    def test_sample_then_scan(self):
        """The sample can be fetched and scanned end to end."""
        status, sample = self.request("GET", "/api/sample")
        self.assertEqual(status, 200)
        status, data = self.request("POST", "/api/analyze", body=sample)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["summary"]["findings"], 16)

    def test_invalid_json_gets_400_with_message(self):
        """Broken JSON gets a 400 and a readable error."""
        status, data = self.request("POST", "/api/analyze", body=b"{oops")
        self.assertEqual(status, 400)
        self.assertIn("not valid JSON", json.loads(data)["error"])

    def test_empty_body_rejected(self):
        """An empty request body gets a 400 error."""
        status, _ = self.request("POST", "/api/analyze", body=b"")
        self.assertEqual(status, 400)

    def test_unknown_path_404(self):
        """An unknown path gets a 404 error."""
        status, _ = self.request("GET", "/nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
