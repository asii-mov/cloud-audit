#!/usr/bin/env python3
"""IBM Cloud IAM collection, configuration review, and local metadata controls."""
import argparse
import base64
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from checks import analyze
from transport import AuditError, Client, Evidence

IAM = "https://iam.cloud.ibm.com"
GROUPS = "https://iam.cloud.ibm.com"
VERSION = "2025-10-14"


def part(value):
    return urllib.parse.quote(value, safe="")


def token_account(token):
    """Read account context from an IAM token received directly over verified TLS.

    This is a scope guard, not independent JWT authentication or signature validation.
    """
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return claims.get("account", {}).get("bss")
    except (AttributeError, IndexError, ValueError, TypeError):
        return None


def collect(client, account, regions, evidence):
    inventory, gaps = {}, []

    def rows(api, path, key, label, params=None):
        result = []
        try:
            result.extend(api.pages(path, key, label, params))
        except AuditError as exc:
            gaps.append(str(exc))
            evidence.note(f"The tester could not complete {label}; retained {len(result)} visible records. {exc}")
        return result

    evidence.note("The tester began enumerating service IDs, including the default and named service-ID groups.")
    inventory["service_id_groups"] = rows(client, "/v1/serviceid_groups", "serviceid_groups", "List service-ID groups", {"account_id": account})
    inventory["service_ids"], inventory["api_keys"] = [], []
    for group in [None] + [g["id"] for g in inventory["service_id_groups"] if g.get("id")]:
        params = {"account_id": account, "pagesize": 100}
        if group:
            params["group_id"] = group
        inventory["service_ids"].extend(rows(client, "/v1/serviceids/", "serviceids", "List service IDs", params))
        inventory["api_keys"].extend(rows(client, "/v1/apikeys", "apikeys", "List service-ID API-key metadata",
                                           {**params, "scope": "account", "type": "serviceid"}))
    for key in ("service_ids", "api_keys"):
        inventory[key] = list({r["id"]: r for r in inventory[key] if r.get("id")}.values())
    for version in ("v1", "v2"):
        inventory["policies_" + version] = rows(client, f"/{version}/policies", "policies", f"List {version} IAM policies",
                                                {"account_id": account, "state": "active", "limit": 100})
    inventory["profiles"] = rows(client, "/v1/profiles", "profiles", "List trusted profiles", {"account_id": account, "pagesize": 100})
    for key, suffix, response_key in (("profile_rules", "rules", "rules"), ("profile_links", "links", "links"),
                                      ("profile_identities", "identities", "identities")):
        inventory[key] = {}
        for profile in inventory["profiles"]:
            pid = profile["id"]
            inventory[key][pid] = rows(client, f"/v1/profiles/{part(pid)}/{suffix}", response_key,
                                      f"Review trusted profile {pid}: {suffix}")
    groups_client = Client(GROUPS, evidence, client.token)
    inventory["access_groups"] = rows(groups_client, "/v2/groups", "groups", "List access groups", {"account_id": account, "limit": 100})
    inventory["group_members"], inventory["group_rules"] = {}, {}
    for group in inventory["access_groups"]:
        gid = group["id"]
        inventory["group_members"][gid] = rows(groups_client, f"/v2/groups/{part(gid)}/members", "members",
                                                 f"List members of {gid}", {"membership_type": "all", "limit": 100})
        inventory["group_rules"][gid] = rows(groups_client, f"/v2/groups/{part(gid)}/rules", "rules", f"List dynamic rules of {gid}")
    try:
        inventory["account_settings"] = client.call(f"/v1/accounts/{part(account)}/settings/identity", "Review account IAM settings")
    except AuditError as exc:
        gaps.append(str(exc))
    inventory["instances"] = []
    if regions and token_account(client.token) != account:
        gaps.append("VPC collection skipped: issued token account context could not be matched to the selected account. Use an API key for that account.")
        regions = []
    for region in regions:
        api = Client(f"https://{region}.iaas.cloud.ibm.com", evidence, client.token)
        inventory["instances"].extend(rows(api, "/v1/instances", "instances", f"Review VPC instances in {region}",
                                            {"version": VERSION, "generation": 2, "limit": 100}))
    inventory["collection_errors"] = gaps.copy()
    gaps.extend([
        "Inventory is limited to objects visible to the auditor. Successful empty lists do not prove absence; validate account-wide coverage with the account owner.",
        "Custom role actions, access-group dynamic rule semantics, IAM conditions, enterprise templates, context-based restrictions and service-specific enforcement require manual review.",
        "No workload business-access baseline or Activity Tracker history was supplied; least privilege and unused-key status cannot be conclusively determined.",
        "Profile assumption, resource access, SSRF and local metadata reachability were not exercised by the account scan. Use the scoped metadata command and the engagement runbook.",
        "VPC collection covers only explicitly selected regions; IKS/ROKS runtime RBAC, PowerVS and bare-metal metadata require separate validation.",
    ])
    if not regions:
        gaps.append("No VPC region selected; metadata configuration inventory was not collected.")
    return inventory, gaps


def metadata(args, evidence):
    """Run only inside the explicitly selected IBM VPC instance/workload context."""
    base = "https://api.metadata.cloud.ibm.com" if args.protocol == "https" else "http://169.254.169.254"
    api = Client(base, evidence, local=True)
    data, gaps, findings = {}, [], []
    evidence.note(f"The tester recorded workload context: {args.context}. Expected profile result: {args.expect_profile or 'not tested'}.")
    evidence.note("The tester requested a short-lived identity token from the local IBM metadata service. Proxy routing is disabled for this local request.")
    try:
        token = api.call("/identity/v1/token", "Request local identity token", {"version": VERSION},
                         method="PUT", body={"expires_in": 300}, headers={"Metadata-Flavor": "ibm"})
        if not token.get("access_token"):
            raise AuditError("Metadata did not return an identity token")
        api.token = token["access_token"]
        data["identity_token_issued"] = True
        data["instance"] = api.call("/metadata/v1/instance", "Read current instance metadata", {"version": VERSION})
    except AuditError as exc:
        gaps.append(str(exc))
        evidence.note("Local metadata validation was inconclusive; a failure can reflect routing, protocol, service configuration or access controls.")
        return data, findings, gaps
    evidence.note("The local workload obtained an identity token and read instance metadata. This is expected functionality for permitted processes and does not itself prove abuse.")
    if args.profile_id:
        try:
            token = api.call("/identity/v1/iam_tokens", "Attempt selected trusted profile", {"version": VERSION},
                             method="POST", body={"trusted_profile": {"id": args.profile_id}})
            if not token.get("access_token"):
                raise AuditError("Profile exchange response did not include an IAM token")
            data["profile_token_issued"] = True
            data["profile_id"] = args.profile_id
            evidence.note("IAM token issuance succeeded for the selected profile. No conclusion about a particular resource follows from issuance alone.")
            if args.expect_profile == "denied":
                findings.append({"id": "PROBE-001", "severity": "HIGH", "status": "OBSERVED_EXPECTATION_MISMATCH",
                                 "title": "Profile token issued where operator expected denial", "resource": args.profile_id,
                                 "narrative": "The tester selected a negative-control profile. The metadata service issued an IAM token. This contradicts the supplied expectation; the owner must confirm the intended trust boundary.",
                                 "recommendation": "Correlate the workload context with the matching trust rule or link and confirm the expectation with the profile owner.",
                                 "evidence": {"profile_token_issued": True, "context": args.context}})
            if args.verify_instance:
                resource_api = Client(f"https://{args.region}.iaas.cloud.ibm.com", evidence, token["access_token"])
                try:
                    result = resource_api.call(f"/v1/instances/{part(args.verify_instance)}", "Read explicitly selected verification instance",
                                               {"version": VERSION, "generation": 2})
                    data["verification"] = {"instance_id": result.get("id"), "read_succeeded": True}
                    evidence.note("The selected profile token successfully read the selected instance. Compare this result with the engagement's approved access matrix.")
                except AuditError as exc:
                    data["verification"] = {"read_succeeded": False, "http_status": exc.status}
                    gaps.append(str(exc))
        except AuditError as exc:
            data["profile_token_issued"] = False
            data["profile_exchange_http_status"] = exc.status
            if exc.status == 403 and args.expect_profile == "denied":
                evidence.note("The selected negative-control exchange returned HTTP 403. This is consistent with expected refusal for this request; confirm the server-side reason in audit events.")
            else:
                gaps.append(str(exc))
    else:
        gaps.append("No trusted profile selected; IAM token exchange and downstream access were not tested.")
    gaps.append("This probe tests the local caller context only. It does not establish application SSRF, container isolation, or the ability of another principal to reach metadata.")
    return data, findings, gaps


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("demo", "scan", "metadata"):
        sub = commands.add_parser(name)
        sub.add_argument("--out", help="New evidence directory; existing directories are never overwritten")
        if name in ("demo", "scan"):
            sub.add_argument("--key-age-days", type=int, default=90)
        if name == "scan":
            sub.add_argument("--account-id", default=os.environ.get("IBMCLOUD_ACCOUNT_ID"))
            sub.add_argument("--region", action="append", default=[], help="Repeat for each VPC region in scope")
        if name == "metadata":
            sub.add_argument("--context", required=True, help="Instance/workload and OS user or container identity for this test")
            sub.add_argument("--protocol", choices=("https", "http"), default="https")
            sub.add_argument("--profile-id", help="One explicitly in-scope trusted profile to test")
            sub.add_argument("--expect-profile", choices=("allowed", "denied"))
            sub.add_argument("--verify-instance", help="One in-scope VPC instance to read using the issued profile token")
            sub.add_argument("--region", help="Region containing --verify-instance")
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if getattr(args, "key_age_days", 1) < 1:
        p.error("--key-age-days must be positive")
    regions = args.region if args.command == "scan" else [getattr(args, "region", None)]
    for region in regions:
        if region and not re.fullmatch(r"[a-z]{2}-[a-z]+", region):
            p.error("region must be an IBM regional identifier such as us-south")
    if args.command == "scan":
        if not args.account_id or not re.fullmatch(r"[a-fA-F0-9]{32}", args.account_id):
            p.error("--account-id or IBMCLOUD_ACCOUNT_ID must contain a 32-character account ID")
        key = os.environ.get("IBMCLOUD_API_KEY") or os.environ.get("IBM_CLOUD_API_KEY")
        if not key:
            p.error("set IBMCLOUD_API_KEY securely in the process environment")
    if args.command == "metadata":
        if bool(args.profile_id) != bool(args.expect_profile):
            p.error("--profile-id and --expect-profile must be supplied together")
        if args.verify_instance and not (args.profile_id and args.region):
            p.error("--verify-instance requires --profile-id and --region")
    out = args.out or str(Path(__file__).parent / "output" / (args.command + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")))
    try:
        evidence = Evidence(out, "SYNTHETIC DEMONSTRATION — NO CLOUD REQUESTS" if args.command == "demo" else "LIVE")
    except OSError as exc:
        p.error(f"cannot create output directory ({type(exc).__name__}); use a new --out path")
    failed = False
    if args.command == "demo":
        from demo import run
        data, gaps = run(evidence)
        findings = analyze(data, args.key_age_days, datetime(2026, 10, 12, tzinfo=timezone.utc))
    elif args.command == "scan":
        evidence.protect(key)
        client = Client(IAM, evidence)
        try:
            result = client.call("/identity/token", "Authenticate auditor", method="POST", form=True,
                                 body={"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": key})
            if not result.get("access_token"):
                raise AuditError("IAM did not return an access token")
            client.token = result["access_token"]
            data, gaps = collect(client, args.account_id, args.region, evidence)
            findings = analyze(data, args.key_age_days)
            failed = bool(data.get("collection_errors"))
        except AuditError as exc:
            data, findings, gaps, failed = {}, [], [str(exc)], True
    else:
        data, findings, gaps = metadata(args, evidence)
        failed = not data.get("identity_token_issued") or any("HTTP" in g or "failure" in g or "did not return" in g or "did not include" in g for g in gaps)
    evidence.finish(data, findings, gaps)
    print(f"Evidence saved to {out}")
    print(f"{len(findings)} review items; {len(gaps)} coverage gaps. Mode: {evidence.mode}")
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
