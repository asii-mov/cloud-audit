import contextlib
import copy
import io
import json
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import audit
from checks import analyze
from demo import fixture
from transport import AuditError, Client, Evidence, NoRedirect


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Evidence(Path(self.temp.name) / "run", "TEST FIXTURES ONLY")

    def test_demo_end_to_end_no_network(self):
        output = Path(self.temp.name) / "demo"
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network forbidden")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(["demo", "--out", str(output)]), 0)
        report = json.loads((output / "report.json").read_text())
        self.assertIn("SYNTHETIC", report["mode"])
        self.assertEqual(len(report["findings"]), 10)
        self.assertEqual(len(report["events"]), 11)
        self.assertIn("tester@ibm-audit$ curl", (output / "transcript.txt").read_text())
        import hashlib
        for name, digest in json.loads((output / "SHA256SUMS.json").read_text()).items():
            self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)

    def test_narrow_policy_not_flagged(self):
        data = fixture()
        data["policies_v1"] = []
        data["policies_v2"] = [data["policies_v2"][1]]
        self.assertFalse(any(f["id"].startswith("IAM") for f in analyze(data)))

    def test_v2_inherited_grant_correlates_service_id_and_profile(self):
        found = [f for f in analyze(fixture()) if f["resource"] == "Policy-DEMO-GROUP"]
        self.assertEqual(len(found), 1)
        self.assertEqual(set(found[0]["evidence"]["affected_principals"]), {"iam-ServiceId-DEMO-BACKUP", "iam-Profile-DEMO"})

    def test_conditional_and_tag_scopes_are_not_claimed_broad(self):
        for field, value in [("rule", {"conditions": []}), ("pattern", "time-based-conditions:once")]:
            data = fixture()
            data["policies_v1"][0][field] = value
            self.assertFalse(any(f["resource"] == "Policy-DEMO-DIRECT" for f in analyze(data)))
        data = fixture()
        data["policies_v1"][0]["resources"][0]["tags"] = [{"name": "env", "value": "test"}]
        self.assertFalse(any(f["resource"] == "Policy-DEMO-DIRECT" for f in analyze(data)))

    def test_deleted_policy_ignored_and_versions_deduplicated(self):
        data = fixture()
        data["policies_v1"][0]["state"] = "deleted"
        data["policies_v1"].append(copy.deepcopy(data["policies_v2"][0]))
        found = analyze(data)
        self.assertFalse(any(f["resource"] == "Policy-DEMO-DIRECT" for f in found))
        self.assertEqual(sum(f["resource"] == "Policy-DEMO-GROUP" for f in found), 1)

    def test_key_age_is_creation_age_not_inactivity(self):
        found = analyze(fixture(), at=datetime(2026, 10, 12, tzinfo=timezone.utc))
        key = next(f for f in found if f["id"].startswith("KEY"))
        self.assertEqual(key["evidence"]["age_days"], 649)
        self.assertIn("does not prove inactivity", key["narrative"])

    def test_exact_compute_binding_suppresses_broad_rule_heuristic(self):
        data = fixture()
        data["profile_rules"]["Profile-DEMO"][0]["conditions"].append({"claim": "crn", "operator": "EQUALS", "value": "crn:exact:fixture"})
        self.assertFalse(any(f["title"] == "Compute trust rule needs boundary validation" for f in analyze(data)))

    def test_redaction_and_terminal_controls(self):
        self.evidence.protect("TEST-SECRET-123")
        self.evidence.request("fixture", "GET", "https://iam.cloud.ibm.com/test", 200,
                              {"description": "echo TEST-SECRET-123\x1b[2J", "api_key": "hidden", "nested": [{"access_token": "hidden-token"}]})
        self.evidence.finish({}, [], [])
        for path in self.evidence.directory.iterdir():
            text = path.read_text()
            self.assertNotIn("TEST-SECRET-123", text)
            self.assertNotIn("hidden-token", text)
            self.assertNotIn("\x1b", text)

    def test_existing_output_is_not_overwritten(self):
        with self.assertRaises(FileExistsError):
            Evidence(self.evidence.directory, "TEST")

    def test_pagination_supports_identity_strings_and_policy_objects(self):
        for next_link in ["/v1/test?pagetoken=two", {"href": "https://iam.cloud.ibm.com/v1/test?start=two"}]:
            client = Client(audit.IAM, self.evidence)
            with patch.object(client, "call", side_effect=[{"rows": [{"id": 1}], "next": next_link}, {"rows": [{"id": 2}]}]):
                self.assertEqual(list(client.pages("/v1/test", "rows", "test")), [{"id": 1}, {"id": 2}])

    def test_pagination_rejects_origin_change_loop_and_wrong_schema(self):
        for response in [{"rows": [], "next": "https://untrusted.example/v1/test"},
                         {"rows": [], "next": "/v1/test"}, {"wrong": []}]:
            client = Client(audit.IAM, self.evidence)
            with patch.object(client, "call", return_value=response), self.assertRaises(AuditError):
                list(client.pages("/v1/test", "rows", "test"))

    def test_redirects_are_not_followed(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://untrusted.example"))

    def test_http_errors_do_not_persist_response_body(self):
        client = Client(audit.IAM, self.evidence, "fixture-token")
        error = urllib.error.HTTPError("https://iam.cloud.ibm.com/test", 403, "Forbidden", {}, io.BytesIO(b'leaked-response-secret'))
        with patch.object(client.opener, "open", side_effect=error), self.assertRaises(AuditError):
            client.call("/test", "test")
        self.assertEqual(self.evidence.events[0]["status"], 403)
        self.assertNotIn("leaked-response-secret", str(self.evidence.events))

    def test_all_service_id_groups_collected_and_failures_retained(self):
        calls = []

        class FakeClient:
            token = "synthetic"

            def __init__(self, *args):
                pass

            def pages(self, path, key, label, params=None):
                calls.append((path, params))
                if key == "serviceid_groups":
                    yield {"id": "Group-fixture"}
                elif key == "serviceids":
                    yield {"id": "Service-" + (params.get("group_id") or "default")}
                elif path == "/v2/policies":
                    yield {"id": "retained-policy"}
                    raise AuditError("fixture HTTP 403", 403)

            def call(self, *args):
                return {}

        with patch("audit.Client", FakeClient):
            data, gaps = audit.collect(FakeClient(), "0" * 32, [], self.evidence)
        self.assertEqual(len(data["service_ids"]), 2)
        self.assertEqual(data["policies_v2"], [{"id": "retained-policy"}])
        self.assertIn("fixture HTTP 403", data["collection_errors"])
        self.assertTrue(any(params and params.get("group_id") == "Group-fixture" for _, params in calls))

    def test_metadata_negative_control_success_is_mismatch_not_proven_resource_access(self):
        args = audit.parser().parse_args(["metadata", "--context", "synthetic-container", "--profile-id", "Profile-fixture", "--expect-profile", "denied"])
        with patch.object(Client, "call", side_effect=[{"access_token": "fixture-local"}, {"id": "fixture-instance"}, {"access_token": "fixture-iam"}]):
            data, findings, gaps = audit.metadata(args, self.evidence)
        self.assertTrue(data["profile_token_issued"])
        self.assertEqual(findings[0]["status"], "OBSERVED_EXPECTATION_MISMATCH")
        self.assertNotIn("verification", data)

    def test_metadata_403_and_network_failure_are_distinguished(self):
        args = audit.parser().parse_args(["metadata", "--context", "fixture", "--profile-id", "Profile-fixture", "--expect-profile", "denied"])
        with patch.object(Client, "call", side_effect=[{"access_token": "fixture"}, {"id": "fixture"}, AuditError("fixture HTTP 403", 403)]):
            data, findings, gaps = audit.metadata(args, self.evidence)
        self.assertFalse(findings)
        self.assertEqual(data["profile_exchange_http_status"], 403)
        self.assertFalse(any("HTTP 403" in gap for gap in gaps))
        with patch.object(Client, "call", side_effect=AuditError("fixture transport failure")):
            data, findings, gaps = audit.metadata(args, self.evidence)
        self.assertIn("fixture transport failure", gaps)
        self.assertFalse(data.get("identity_token_issued"))

    def test_scan_requires_credentials_before_network(self):
        with patch.dict("os.environ", {}, clear=True), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            audit.main(["scan", "--account-id", "0" * 32])
        self.assertEqual(caught.exception.code, 2)

    def test_metadata_requires_explicit_expectation(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            audit.main(["metadata", "--context", "fixture", "--profile-id", "Profile-fixture"])

    def test_token_account_scope_guard(self):
        import base64
        encoded = base64.urlsafe_b64encode(json.dumps({"account": {"bss": "0" * 32}}).encode()).decode().rstrip("=")
        self.assertEqual(audit.token_account("fixture." + encoded + ".fixture"), "0" * 32)
        self.assertIsNone(audit.token_account("not-a-jwt"))

    def test_client_captures_redacted_success_and_actual_headers(self):
        client = Client(audit.IAM, self.evidence)
        response = io.BytesIO(b'{"access_token": "synthetic-token-value", "expires_in": 300}')
        response.status = 200
        with patch.object(client.opener, "open", return_value=response):
            result = client.call("/identity/v1/token", "fixture", method="PUT", body={"expires_in": 300}, headers={"Metadata-Flavor": "ibm"})
        self.assertEqual(result["access_token"], "synthetic-token-value")
        self.assertNotIn("synthetic-token-value", str(self.evidence.events))
        self.assertIn("Metadata-Flavor: ibm", "\n".join(self.evidence.lines))


if __name__ == "__main__":
    unittest.main()
