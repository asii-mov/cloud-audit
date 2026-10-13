# Engagement procedure and report narrative

## Establish the intended integration

Record the account IDs, regions, source service/workload, target service/resource, required actions, permitted identities and owner. For each path, write down one intended access case and one denied sibling-workload or resource case. Confirm the auditor's visibility against an owner-supplied inventory. Assign an evidence directory to each run and retain its hashes with the engagement record.

The automated account scan provides configuration evidence. Test only selected resources in the later runtime stage. A broad grant is not automatically excessive if the workload's documented responsibility requires it. Avoid interpreting missing data, empty lists or access-denied responses as a passing control.

## 1. Service IDs, API keys and least privilege

Run `python audit.py scan --auth cli --account-id ACCOUNT_ID --out output/iam-review` from this folder with your existing IBM Cloud CLI login. The expected account must match the CLI target. Alternatively, select `--auth api-key` and supply your own key locally. Add the regions in scope for VPC posture.

The tester enumerates service IDs across their groups, enumerates service-ID key metadata, and correlates the identities with direct policies and visible group memberships. Review platform and service roles separately. Check resource group, service instance, resource type/ID, access tags, conditions and inherited grants; a narrow policy does not cancel a broader additive grant.

Compare the resulting action set to the integration's required operation. Review custom roles at the action level, especially policy management, service-ID key creation, access-group membership administration, trusted-profile rule/link/identity administration and role administration. Possession of any of those permissions can create an escalation path even where the role's name sounds harmless. The toolkit flags custom roles for review but does not compute this permission closure.

Correlate key IDs and principal IDs with Activity Tracker and service logs. Creation age alone cannot establish last use. Check keys in local CI variables, build logs, deployment artifacts, Terraform state and service bindings through separately approved secret-handling procedures; do not copy secret values into the report. Prefer evidence showing the secret's presence, owner and location without exposing it. Verify that disabling/removing a credential and handling already-issued tokens follows IBM's documented lifecycle behavior before claiming immediate revocation.

## 2. Trusted profiles and compute identity

Review all alternative trust rules, each rule's AND conditions, direct compute links and explicit identities permitted to assume the profile. Review the profile's direct and inherited access. Check source account/CRN, compute resource type and claim sources; names and tags can be mutable, while a direct resource binding has different lifecycle risks.

For IKS/ROKS, determine who can create pods, select service accounts, create/recreate a matching namespace or service account, or alter RBAC. IBM documents that future namespaces/service accounts with matching names can establish trust. A namespace claim alone does not establish intended workload identity. A fixed cluster link still needs workload-level RBAC review.

For VPC, run the `metadata` command from the intended workload and from a separately selected negative-control context, with the same selected profile and explicit expected result. Record the actual execution context and corroborate it using your normal host/container evidence. If a token is issued unexpectedly, determine the exact matching rule or link. Optionally read a selected harmless resource with `--verify-instance` to demonstrate concrete access. The implementation does not create a matching workload, change tags, forge claims or modify trust policies.

IKS/ROKS token exchange and PowerVS identity validation require their own native workflow; a VPC metadata probe does not test them. A configuration-only profile finding must remain a hypothesis until exercised and compared against the owner's intended boundary.

## 3. Metadata service exposure and abuse

Review `metadata_service.enabled`, `protocol` and `response_hop_limit` in regional instance inventory. Decide which applications and containers should reach the service. IBM's local token operation requires a PUT and `Metadata-Flavor: ibm`; a basic GET-only SSRF primitive does not automatically satisfy these requirements.

Use the local metadata command to document whether the selected process can request a token and read instance metadata. Record whether this is intended. HTTPS protects transport but does not by itself prevent an allowed local process from requesting a token. A larger response hop limit can be necessary for containers; test the actual topology rather than treating the setting as proof of exposure.

For a suspected SSRF in an in-scope application, use a controlled reproduction that demonstrates its permitted URL schemes, request methods, headers, redirect handling and response visibility. Correlate application logs and the metadata probe. Do not equate shell access on the host with SSRF from an application. The toolkit does not inject SSRF payloads into applications.

Metadata initialization data can contain bootstrap secrets. This toolkit deliberately does not retrieve it. Review the source deployment configuration for secret placement and record redacted evidence separately when that check is in scope. For remediation, evaluate disabling unused metadata, HTTPS where compatible, suitable hop limits, process/container egress restrictions, and narrower trusted profiles. Retest both permitted and denied callers so that hardening does not silently break the intended integration.

## Additional IBM IAM attack vectors

| Vector | Tester procedure and decision evidence |
| --- | --- |
| Broad or cross-account service authorization | Inspect both source and target account/service/resource attributes. Confirm the external account owner, intended source instance and target action. Compare an intended source with a sibling instance. |
| Delegated/dependent-service authorizations | Review policies created by source services for dependencies. IBM documents that dependent resources may be in the source account while their target-account policies remain visible. Trace the full integration chain. |
| Privilege administration paths | Review who can create API keys for a powerful service ID, edit its access groups/policies, modify a custom role, or change trusted-profile rules/links/identities. Confirm action-level permissions and an approved non-destructive proof before reporting escalation. |
| Dynamic access-group claims | Inspect IdP, conditions, expiration and attribute ownership. Review whether users can influence the matching IdP attribute. Current dynamic membership is not an exhaustive list of everyone who might match later. |
| Access-tag and resource-placement changes | Identify identities allowed to change tags, create resources in privileged resource groups or deploy workloads that match trust criteria. Test this only in isolated resources with an agreed restoration plan. |
| Context-based restrictions (CBR) | Check supported service/API coverage, network zones, allowed service references, endpoint types and enforcement state. Disabled or report-only rules do not block access. Run selected positive/negative resource requests and correlate service audit events. |
| Cross-account identity restrictions | Review IAM resource settings and account allowlists. Distinguish report-only decisions from enforced denials; corroborate `iam-access-management.account-settings.eval` events where applicable. |
| Long-lived or embedded credentials | Correlate key creation, ownership, deployment location and observed use. Check CI/service bindings and state artifacts without exposing key values. MFA on a human login is not evidence that every API-key workload has the same protection. |
| Excessive federation/session trust | Review SAML profile realms, claim provenance, session lifetime and deprovisioning behavior. Do not treat SAML user trust and compute-resource trust as interchangeable. |
| Audit and detection gaps | Verify IAM and target-service events arrive in the expected Activity Tracker/Cloud Logs destination with useful principal/resource identifiers, retention and alerting. Absence of an event is not proof no access happened. |

The table is a manual test plan. Only the checks described as implemented in the README run automatically.

## Narrative for the final report

Use actual run identifiers and observed responses. The wording below is a template, not a completed finding:

> The tester queried IAM service-ID and API-key metadata in account `[account]` and reviewed the returned identities against the approved integration inventory. The tester correlated `[principal]` with direct policy `[policy]` and inherited membership `[group]`. The collected policy granted `[role/actions]` over `[scope]`; the integration owner confirmed that the workload required only `[approved actions/resources]`.
>
> The tester then reviewed trusted profile `[profile]`, including its rules, linked compute resources and permitted identities. From `[documented workload context]`, the tester ran the selected profile test and received `[actual status/result]`. The expected outcome for this context was `[allow/deny]`. `[A resource read was performed and returned … / No downstream resource access was tested.]`
>
> The tester reviewed the instance metadata configuration and observed `[settings]`. The local probe established `[specific observed behavior]`. `[Application-level SSRF was separately demonstrated with evidence … / Application-level SSRF was not tested.]` The result supports `[bounded conclusion]`; remaining limitations are `[visibility, missing logs, untested regions or business context]`.

Include the policy/rule IDs, request timestamp, result, intended boundary, concrete impact, remediation and retest result. Preserve `REVIEW_REQUIRED` until the access requirement is confirmed. Never replace a failed collection or unrun test with a fabricated terminal response.
