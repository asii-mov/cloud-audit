"""Conservative configuration heuristics; these do not prove exploitability."""
from datetime import datetime, timezone


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
