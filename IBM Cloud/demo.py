"""Synthetic fixtures only. No credentials and no network calls."""


def fixture():
    account = "00000000000000000000000000000000"
    admin = {"role_id": "crn:v1:bluemix:public:iam::::role:Administrator"}
    reader = {"role_id": "crn:v1:bluemix:public:iam::::serviceRole:Reader"}

    def attrs(**items):
        return {"attributes": [{"name": k, "value": v} for k, v in items.items()]}

    return {
        "service_id_groups": [{"id": "ServiceIdGroup-DEMO", "name": "demo-integrations"}],
        "service_ids": [
            {"id": "ServiceId-DEMO-CI", "iam_id": "iam-ServiceId-DEMO-CI", "name": "demo-ci-integration"},
            {"id": "ServiceId-DEMO-BACKUP", "iam_id": "iam-ServiceId-DEMO-BACKUP", "name": "demo-backup-worker"}],
        "api_keys": [{"id": "ApiKey-DEMO-OLD", "iam_id": "iam-ServiceId-DEMO-CI", "name": "demo-ci-key", "created_at": "2025-01-01T00:00:00Z"}],
        "policies_v1": [
            {"id": "Policy-DEMO-DIRECT", "type": "access", "roles": [admin],
             "subjects": [attrs(iam_id="iam-ServiceId-DEMO-CI")], "resources": [attrs(accountId=account)]},
            {"id": "Policy-DEMO-S2S", "type": "authorization", "roles": [reader],
             "subjects": [attrs(accountId=account, serviceName="cloud-object-storage")],
             "resources": [attrs(accountId=account, serviceName="kms")]}],
        "policies_v2": [
            {"id": "Policy-DEMO-GROUP", "type": "access", "control": {"grant": {"roles": [admin]}},
             "subject": attrs(access_group_id="AccessGroup-DEMO"), "resource": attrs(accountId=account, serviceName="is")},
            {"id": "Policy-DEMO-NARROW", "type": "access", "control": {"grant": {"roles": [reader]}},
             "subject": attrs(iam_id="iam-ServiceId-DEMO-BACKUP"), "resource": attrs(accountId=account, serviceName="cloud-object-storage", serviceInstance="Instance-DEMO-BUCKET") }],
        "access_groups": [{"id": "AccessGroup-DEMO", "name": "demo-operations"}],
        "group_members": {"AccessGroup-DEMO": [{"iam_id": "iam-ServiceId-DEMO-BACKUP", "type": "serviceid"}, {"iam_id": "iam-Profile-DEMO", "type": "profile"}]},
        "group_rules": {"AccessGroup-DEMO": []},
        "profiles": [{"id": "Profile-DEMO", "iam_id": "iam-Profile-DEMO", "name": "demo-compute-profile"}],
        "profile_rules": {"Profile-DEMO": [{"id": "Rule-DEMO", "type": "Profile-CR", "cr_type": "IKS_SA", "conditions": [
            {"claim": "namespace", "operator": "EQUALS", "value": "default"}]}]},
        "profile_links": {"Profile-DEMO": [{"id": "Link-DEMO", "cr_type": "IKS_SA", "link": {"crn": "crn:v1:bluemix:public:containers-kubernetes:us-south:a/00000000000000000000000000000000::cluster:DEMO", "namespace": "default", "name": "default"}}]},
        "profile_identities": {"Profile-DEMO": [{"iam_id": "iam-ServiceId-DEMO-PARTNER", "identifier": "ServiceId-DEMO-PARTNER", "type": "serviceid"}]},
        "account_settings": {"restrict_create_service_id": "NOT_RESTRICTED", "restrict_create_platform_apikey": "RESTRICTED"},
        "instances": [{"id": "Instance-DEMO", "name": "demo-integration-host", "metadata_service": {"enabled": True, "protocol": "http", "response_hop_limit": 2}}],
    }


def run(evidence):
    data = fixture()
    evidence.note("SYNTHETIC WALKTHROUGH: The following requests and responses are rendered from fixtures. No tester queried a real account. All identifiers are invented.")
    for label, path, key, response_key in [
        ("Enumerate workload identities", "/v1/serviceids/", "service_ids", "serviceids"),
        ("Enumerate API-key metadata", "/v1/apikeys", "api_keys", "apikeys"),
        ("Review direct grants and service authorizations", "/v1/policies", "policies_v1", "policies"),
        ("Review inherited workload permissions", "/v2/policies", "policies_v2", "policies"),
        ("Enumerate trusted profiles", "/v1/profiles", "profiles", "profiles"),
    ]:
        evidence.request("SYNTHETIC: " + label, "GET", "https://iam.cloud.ibm.com" + path + "?account_id=00000000000000000000000000000000",
                         200, {response_key: data[key]}, authenticated=True)
        evidence.note("SYNTHETIC: The tester reviewed the returned fixture records and correlated their identifiers with subsequent policy and trust checks.")
    for suffix, key, response_key in [("rules", "profile_rules", "rules"), ("links", "profile_links", "links"), ("identities", "profile_identities", "identities")]:
        evidence.request("SYNTHETIC: Review profile " + suffix, "GET", "https://iam.cloud.ibm.com/v1/profiles/Profile-DEMO/" + suffix,
                         200, {response_key: data[key]["Profile-DEMO"]}, authenticated=True)
    evidence.request("SYNTHETIC: Correlate access-group membership", "GET", "https://iam.cloud.ibm.com/v2/groups/AccessGroup-DEMO/members",
                     200, {"members": data["group_members"]["AccessGroup-DEMO"]}, authenticated=True)
    evidence.request("SYNTHETIC: Review account creation controls", "GET", "https://iam.cloud.ibm.com/v1/accounts/00000000000000000000000000000000/settings/identity",
                     200, data["account_settings"], authenticated=True)
    evidence.request("SYNTHETIC: Review metadata configuration", "GET", "https://us-south.iaas.cloud.ibm.com/v1/instances?version=2025-10-14&generation=2",
                     200, {"instances": data["instances"]}, authenticated=True)
    return data, ["Synthetic data only; no live account, identity assumption, metadata endpoint, SSRF path or resource access was tested.",
                  "Demonstration key ages use 2026-10-12 as the fixed assessment date.",
                  "All rule matches need business-context review; absence of a finding is not a security pass."]
