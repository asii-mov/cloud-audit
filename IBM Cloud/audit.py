#!/usr/bin/env python3
"""Standalone IBM Cloud IAM collection, configuration review, and metadata controls."""
import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


IAM = "https://iam.cloud.ibm.com"
GROUPS = "https://iam.cloud.ibm.com"
VERSION = "2025-10-14"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Evidence:
    def __init__(self, directory, mode):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.mode = mode
        self.events = []
        self.secrets = set()
        self.lines = ["IBM CLOUD | IAM ENGAGEMENT TRANSCRIPT", f"Mode: {mode}",
                      f"Started: {now()}",
                      "Prompts below render HTTP requests executed by Python, not an interactive shell.",
                      "Secrets are redacted. Review notes are automated assessment, not human sign-off.",
                      "Configuration findings are hypotheses until business need and access are validated.", ""]

    def protect(self, value):
        if isinstance(value, str) and value:
            self.secrets.add(value)

    def clean(self, value):
        if isinstance(value, dict):
            return {str(k): "[REDACTED]" if re.sub(r"[^a-z]", "", str(k).lower()) in {
                "apikey", "accesstoken", "refreshtoken", "authorization", "password",
                "secret", "clientsecret", "userdata", "privatekey", "token", "idtoken"
            } else self.clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            for secret in sorted(self.secrets, key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]")
            # Prevent terminal control sequences and embedded prompts in resource names.
            return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in value)
        return value

    def note(self, text):
        self.lines.append(f"[{now()}] REVIEW: {self.clean(text)}")

    def request(self, label, method, url, status, response, body=None, authenticated=False, headers=None, form=False):
        event = self.clean({"time": now(), "label": label, "method": method,
                            "url": url, "status": status, "response": response,
                            "request_body": body, "request_headers": headers or {}})
        self.events.append(event)
        command = f"curl -sS -X {method} {shlex.quote(self.clean(url))}"
        if authenticated:
            command += " -H 'Authorization: Bearer [REDACTED]'"
        for name, value in (headers or {}).items():
            if name.lower() != "authorization":
                command += " -H " + shlex.quote(self.clean(f"{name}: {value}"))
        if body is not None:
            rendered = urllib.parse.urlencode(self.clean(body)) if form else json.dumps(self.clean(body), sort_keys=True)
            command += " --data " + shlex.quote(rendered)
        self.lines.extend(["", f"[{event['time']}] {self.clean(label)}", f"tester@ibm-audit$ {command}",
                           f"HTTP {status}", json.dumps(event["response"], indent=2, sort_keys=True)])

    def finish(self, inventory, findings, gaps):
        self.note(f"Review completed: {len(findings)} review items; {len(gaps)} coverage gaps.")
        for f in findings:
            self.note(f"{f['id']} [{f['severity']}] {f['title']} | {f['resource']}")
            self.note(f["narrative"])
            self.note("Recommended follow-up: " + f["recommendation"])
        for gap in gaps:
            self.note("COVERAGE GAP: " + gap)
        if not findings:
            self.note("No implemented heuristic matched. This is not a least-privilege certification.")
        report = {"schema_version": 1, "mode": self.mode, "completed_at": now(),
                  "findings": findings, "coverage_gaps": gaps, "events": self.events,
                  "inventory": inventory}
        files = {"transcript.txt": "\n".join(self.lines) + "\n",
                 "report.json": json.dumps(self.clean(report), indent=2, sort_keys=True) + "\n"}
        for name, content in files.items():
            path = self.directory / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        manifest = {name: hashlib.sha256((self.directory / name).read_bytes()).hexdigest() for name in files}
        (self.directory / "SHA256SUMS.json").write_text(json.dumps(manifest, indent=2) + "\n")


class Client:
    def __init__(self, base, evidence, token=None, local=False):
        self.base = base.rstrip("/")
        self.evidence = evidence
        self.token = token
        self.evidence.protect(token)
        handlers = [NoRedirect()]
        if local:
            handlers.append(urllib.request.ProxyHandler({}))
        self.opener = urllib.request.build_opener(*handlers)

    def url(self, path, params=None):
        url = urllib.parse.urljoin(self.base + "/", path)
        target, origin = urllib.parse.urlsplit(url), urllib.parse.urlsplit(self.base)
        if (target.scheme, target.netloc) != (origin.scheme, origin.netloc) or target.username or target.fragment:
            raise AuditError("Refused a URL outside the configured API origin")
        if params:
            url += ("&" if target.query else "?") + urllib.parse.urlencode(params)
        return url

    def call(self, path, label, params=None, method="GET", body=None, form=False, headers=None):
        url = self.url(path, params)
        hdr = {"Accept": "application/json", **(headers or {})}
        if self.token:
            hdr["Authorization"] = "Bearer " + self.token
        data = None
        if body is not None:
            data = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
            hdr["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        req = urllib.request.Request(url, data=data, headers=hdr, method=method)
        try:
            with self.opener.open(req, timeout=20) as response:
                status = response.status
                raw = response.read(16 * 1024 * 1024 + 1)
                if len(raw) > 16 * 1024 * 1024:
                    raise AuditError("Response exceeded 16 MiB; narrow collection scope")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise AuditError("Expected a JSON object")
        except urllib.error.HTTPError as exc:
            # Never persist arbitrary error bodies: services can echo credentials.
            self.evidence.request(label, method, url, exc.code, {"error": "HTTP request failed; body omitted"}, body, bool(self.token), hdr, form)
            raise AuditError(f"{label}: HTTP {exc.code}", exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, AuditError) as exc:
            self.evidence.request(label, method, url, "ERROR", {"error_type": type(exc).__name__}, body, bool(self.token), hdr, form)
            raise AuditError(f"{label}: transport or JSON response failure ({type(exc).__name__})") from None
        for name in ("access_token", "refresh_token", "apikey", "id_token"):
            self.evidence.protect(result.get(name))
        self.evidence.request(label, method, url, status, result, body, bool(self.token), hdr, form)
        return result

    def pages(self, path, key, label, params=None):
        current = self.url(path, params)
        expected_path = urllib.parse.urlsplit(current).path
        seen = set()
        for _ in range(1000):
            current = self.url(current)
            if urllib.parse.urlsplit(current).path != expected_path or current in seen:
                raise AuditError(f"{label}: invalid or repeated pagination URL")
            seen.add(current)
            response = self.call(current, label)
            rows = response.get(key)
            if not isinstance(rows, list) or not all(isinstance(x, dict) for x in rows):
                raise AuditError(f"{label}: missing or malformed {key} array")
            yield from rows
            following = response.get("next")
            if not following:
                return
            if isinstance(following, dict):
                following = following.get("href")
            if not isinstance(following, str) or not following:
                raise AuditError(f"{label}: malformed pagination link")
            current = urllib.parse.urljoin(current, following)
        raise AuditError(f"{label}: pagination limit reached")


def attributes(item):
    return {a.get("name"): a.get("value") for a in item.get("attributes", [])}


def policy_parts(policy):
    # IAM v1 and v2 have different grant, subject and resource envelopes.
    roles = policy.get("roles", policy.get("control", {}).get("grant", {}).get("roles", []))
    subjects = policy.get("subjects", [policy["subject"]] if "subject" in policy else [])
    resources = policy.get("resources", [policy["resource"]] if "resource" in policy else [])
    return roles, subjects, resources


def analyze(data, key_age_days=90, at=None):
    at = at or datetime.now(timezone.utc)
    findings = []

    def add(code, severity, title, resource, narrative, recommendation, evidence):
        findings.append({"id": f"{code}-{len(findings) + 1:03d}", "severity": severity,
                         "status": "REVIEW_REQUIRED", "title": title, "resource": resource,
                         "narrative": narrative, "recommendation": recommendation, "evidence": evidence})

    principals = {s.get("iam_id"): s.get("name", s.get("id")) for s in data.get("service_ids", [])}
    principals.update({p.get("iam_id"): p.get("name", p.get("id")) for p in data.get("profiles", [])})
    group_members = data.get("group_members", {})
    policies = {}
    for p in data.get("policies_v1", []) + data.get("policies_v2", []):
        # Prefer v2 representation of a policy returned in both APIs.
        policies[p.get("id", str(p))] = p
    for policy in policies.values():
        if policy.get("state", "active") != "active":
            continue
        roles, subjects, resources = policy_parts(policy)
        names = [r.get("role_id", "").rsplit(":", 1)[-1] for r in roles]
        privileged = sorted(set(names) & {"Administrator", "Editor", "Manager"})
        subject_attrs = [attributes(s) for s in subjects]
        affected = []
        for s in subject_attrs:
            if s.get("iam_id") in principals:
                affected.append(s["iam_id"])
            group = s.get("access_group_id")
            affected.extend(m.get("iam_id") for m in group_members.get(group, []) if m.get("iam_id") in principals)
        resource = policy.get("id", "unknown-policy")
        scope = [attributes(r) for r in resources]
        # Tags, conditional rules and nontrivial operators require full policy review.
        conditional = bool(policy.get("rule") or policy.get("pattern") or any(
            r.get("tags") or any(a.get("operator", "stringEquals") != "stringEquals" for a in r.get("attributes", []))
            for r in resources))
        broad = bool(resources) and not conditional and any(
            set(s) <= {"accountId", "serviceName", "serviceType", "serviceGroupId"} for s in scope)
        if privileged and affected and broad:
            add("IAM", "HIGH", "Broad privileged grant to a workload identity", resource,
                f"The tester queried IAM policies and correlated direct subjects and visible group membership. "
                f"Policy {resource} grants {privileged} to {sorted(set(affected))} without a resource-group or instance restriction in at least one resource scope. "
                "This is a least-privilege review candidate; required business access has not been supplied.",
                "Confirm required actions with the workload owner; scope grants to required resources and use narrower roles.",
                {"policy": policy, "affected_principals": sorted(set(affected))})
        if policy.get("type") == "authorization":
            source_broad = any("serviceName" in s and not any(k in s for k in ("serviceInstance", "resource", "resourceGroupId")) for s in subject_attrs)
            if source_broad or broad:
                add("S2S", "MEDIUM", "Broad service-to-service authorization", resource,
                    "The tester reviewed the authorization source and target attributes. At least one side is scoped above an individual instance or resource group. "
                    "This can extend trust to additional service instances; it is not proof of a confused-deputy exploit.",
                    "Compare source account, source instance, target instance and granted role against the intended integration; test a denied sibling instance in a controlled environment.",
                    {"policy": policy})
        if any("custom" in r.get("role_id", "").lower() for r in roles):
            add("ROLE", "INFO", "Custom role requires action-level review", resource,
                "The tester observed a custom role. Built-in role-name heuristics do not establish its effective permissions.",
                "Review the custom role's action definition, including IAM policy, credential and trusted-profile administration.", {"policy": policy})

    for key in data.get("api_keys", []):
        try:
            created = datetime.fromisoformat(key["created_at"].replace("Z", "+00:00"))
            age = (at - created).days
        except (KeyError, ValueError, TypeError):
            add("KEY", "INFO", "API-key creation age could not be assessed", key.get("id", "unknown"),
                "The tester enumerated key metadata but could not interpret its creation timestamp.",
                "Review the key's lifecycle in IAM and verify its owner and usage.", {"key": key})
            continue
        if age >= key_age_days:
            add("KEY", "MEDIUM", "Long-lived API key requires lifecycle review", key.get("id", "unknown"),
                f"The tester enumerated API-key metadata and observed a creation age of {age} days, exceeding the engagement threshold of {key_age_days} days. "
                "Creation age does not prove inactivity, compromise, or noncompliance with IBM policy. Keys inherit their identity's permissions.",
                "Confirm usage and ownership, rotate through a tested deployment process, and consider compute identity instead of a stored API key.", {"key": key, "age_days": age})

    for profile_id, rules in data.get("profile_rules", {}).items():
        for rule in rules:
            if rule.get("type") != "Profile-CR":
                continue
            conditions = rule.get("conditions", [])
            exact_binding = any(c.get("claim") in {"crn", "id", "resource_id"}
                                and c.get("operator") == "EQUALS" and c.get("value")
                                and "*" not in str(c["value"]) for c in conditions)
            if not exact_binding:
                add("TRUST", "MEDIUM", "Compute trust rule needs boundary validation", profile_id,
                    "The tester reviewed a compute-resource claim rule without an exact CRN or resource-ID condition recognized by this heuristic. "
                    "Other conditions may still restrict trust. Resources created later with matching names, namespaces, service accounts or tags may qualify.",
                    "Review every AND condition and alternative rule; identify who can create matching resources or change claims. Test an approved positive control and a disallowed sibling workload.",
                    {"rule": rule})
    for profile_id, identities in data.get("profile_identities", {}).items():
        if identities:
            add("TRUST", "INFO", "Explicit trusted-profile identities require ownership review", profile_id,
                "The tester enumerated identities permitted to assume this profile. Explicit trust is expected functionality; business intent and cross-account ownership need verification.",
                "Validate service IDs, service CRNs and user account restrictions against the approved integration inventory.", {"identities": identities})
    for profile_id, links in data.get("profile_links", {}).items():
        for link in links:
            binding = link.get("link", {})
            if link.get("cr_type") in {"IKS_SA", "ROKS_SA"} and (binding.get("namespace") == "default" or binding.get("name") == "default"):
                add("TRUST", "MEDIUM", "Compute link uses a default Kubernetes identity", profile_id,
                    "The tester reviewed a direct compute link using a default namespace or service account. Shared workload placement may widen who can use this profile.",
                    "Check Kubernetes RBAC, pod creation and service-account selection permissions; isolate the intended workload identity.", {"link": link})

    for instance in data.get("instances", []):
        metadata = instance.get("metadata_service", {})
        if not metadata.get("enabled"):
            continue
        if metadata.get("protocol") == "http":
            add("IMDS", "LOW", "Metadata uses HTTP", instance.get("id", "unknown"),
                "The tester queried VPC instance configuration and observed enabled metadata over HTTP. This alone does not demonstrate SSRF or token theft.",
                "Assess image compatibility and enable HTTPS metadata where supported; restrict process access to the local endpoint.", {"metadata_service": metadata})
        hops = metadata.get("response_hop_limit")
        if isinstance(hops, int) and hops > 1:
            add("IMDS", "MEDIUM", "Metadata response hop limit exceeds one", instance.get("id", "unknown"),
                f"The tester observed a metadata response hop limit of {hops}. This can support additional network hops, including container workloads, when routing permits.",
                "Confirm the required container topology; minimize the hop limit and validate access from both intended and unintended workload contexts.", {"metadata_service": metadata})

    settings = data.get("account_settings", {})
    for name in ("restrict_create_service_id", "restrict_create_platform_apikey"):
        if settings.get(name) == "NOT_RESTRICTED":
            add("GOV", "LOW", "Credential or identity creation is not restricted", name,
                f"The tester reviewed account IAM settings and observed {name}=NOT_RESTRICTED. This increases the importance of ownership and lifecycle controls.",
                "Evaluate restricting creation to approved operators and monitor new credentials and service IDs.", {name: settings[name]})
    return findings


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
    for name in ("scan", "metadata"):
        sub = commands.add_parser(name)
        sub.add_argument("--out", help="New evidence directory; existing directories are never overwritten")
        if name == "scan":
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
        evidence = Evidence(out, "LIVE")
    except OSError as exc:
        p.error(f"cannot create output directory ({type(exc).__name__}); use a new --out path")
    failed = False
    if args.command == "scan":
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
