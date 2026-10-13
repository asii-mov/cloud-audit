# IBM Cloud IAM service-to-service audit

Python 3.10+; standard library only. No package installation is needed.

This toolkit collects IAM configuration, correlates workload identities with grants, and writes an engagement-style transcript that can be displayed with `cat`. Development and validation use **synthetic data only**. You run live commands separately in your own account.

## Try the screenshot report

From the repository root:

```bash
cd 'IBM Cloud'
python audit.py demo --out output/demo
cat output/demo/transcript.txt
```

Use a new output path for each run. The tool refuses to overwrite an existing directory. A generated example is included at [examples/demo/transcript.txt](examples/demo/transcript.txt).

Each run produces:

| File | Purpose |
| --- | --- |
| `transcript.txt` | Terminal-style requests, responses, timestamps, tester review narrative, findings and coverage gaps |
| `report.json` | Redacted collected inventory, request events and structured findings |
| `SHA256SUMS.json` | SHA-256 hashes of both evidence files; useful for detecting accidental changes, not a signed attestation |

The displayed `curl` commands are readable equivalents of Python HTTP requests. Python executes the requests; the transcript is not a claim that someone typed `curl`. Demo requests are explicitly labelled synthetic. In live reports, “the tester reviewed” describes automated rule evaluation; the report still needs human validation. Credentials and token fields are redacted. Account IDs, resource names, memberships and policies remain in live evidence, so review files before sharing. Output is excluded from Git.

## Coverage

| Test area | Implemented behavior | Evidence still needed |
| --- | --- | --- |
| Service IDs and API keys | Enumerate default and named service-ID groups, key metadata and creation age | Business access baseline, owner, activity logs and rotation history |
| Least privilege | Correlate direct and visible access-group grants in IAM v1/v2; flag broad Administrator, Editor and Manager grants | Custom-role actions, conditional/tagged grants, deny/context controls and service-specific effective access |
| Service-to-service integration | Review authorization-policy source/target breadth | Intended source/target accounts and instances, delegated authorizations, positive and negative access tests |
| Trusted profiles | Collect claim rules, direct compute links and permitted identities; flag broad compute rules and default Kubernetes identities | Who can create matching compute resources or change claims, cluster RBAC, expected trust matrix |
| Metadata posture | Optional regional VPC instance configuration: protocol and response hop limit | Required topology, OS/process/container access controls and SSRF reachability |
| Local metadata validation | Separately obtain an identity token, read instance metadata, optionally exchange for one selected profile and read one selected VPC instance | Owner-approved expectations, application-level SSRF reproduction and matching audit events |
| Other IAM vectors | Collect account creation controls and group dynamic rules; provide [manual procedures](ENGAGEMENT.md) | CBR enforcement, cross-account restrictions, custom roles, privilege administration and event coverage |

Heuristic severity is triage priority, not an established vulnerability rating. `REVIEW_REQUIRED` is a configuration review item. `OBSERVED_EXPECTATION_MISMATCH` means a live negative-control profile issued a token despite the operator specifying `denied`; business intent and downstream impact still need confirmation.

## Run the account review yourself

Use an auditor identity with access to read the selected account's service-ID groups, service IDs, API-key metadata, trusted profiles and trust relationships, IAM access/authorization policies, access groups and memberships, and account IAM settings. For VPC collection it also needs instance-list access in the selected regions. Have the account owner establish the required read permissions; do not grant broad Administrator simply to suppress collection errors.

IBM list APIs can return only the objects visible to the caller, sometimes with HTTP 200 and an empty list. A successful run is not proof of account-wide visibility. API-key metadata enumeration does not retrieve secret API-key values. The scan does not enumerate all human users' API keys or test stolen credentials.

In your own shell, supply the key without placing its value in command history:

```bash
read -r -s -p 'IBM Cloud API key: ' IBMCLOUD_API_KEY
export IBMCLOUD_API_KEY
export IBMCLOUD_ACCOUNT_ID='YOUR_32_CHARACTER_ACCOUNT_ID'
python audit.py scan --region us-south --region eu-gb --out output/account-review
unset IBMCLOUD_API_KEY
cat output/account-review/transcript.txt
```

Use a key scoped to the intended account. Regional VPC calls are skipped with a collection error unless the IAM-issued token's account context matches the selected account. This context check is not an independent JWT signature validation. `--account-id` overrides `IBMCLOUD_ACCOUNT_ID`; `IBM_CLOUD_API_KEY` is also accepted. Omit `--region` for an IAM-only review. The default key-age review threshold is 90 days; change it with `--key-age-days`. It is an engagement threshold, not an IBM-mandated limit.

The account scan issues GET requests after exchanging the auditor's API key for a token. It does not change policies, credentials or resource configuration. Required HTTPS destinations are `iam.cloud.ibm.com` and each selected `<region>.iaas.cloud.ibm.com`. TLS verification remains enabled, redirects are refused, and pagination is restricted to the original API origin and path. Requests time out after 20 seconds; rerun into a new evidence directory after resolving failures or rate limiting. Tokens are not refreshed automatically during long audits; expired-token failures are retained as coverage gaps.

## Test metadata from your IBM VPC workload

Run this command **inside the selected IBM VPC instance or container**, as the OS/workload identity whose access is being reviewed. The context label is supplied by you, not independently attested by the tool. No metadata requests are issued by `demo` or `scan`.

```bash
python audit.py metadata \
  --context 'test-vsi / application container / uid 1000' \
  --out output/metadata-local
```

This requests a five-minute identity token, holds it in memory and reads instance metadata. HTTPS is the default, using `api.metadata.cloud.ibm.com`. If the instance is deliberately configured for HTTP, select `--protocol http`, which uses the documented link-local address `169.254.169.254`. The probe bypasses process HTTP proxies only for the local metadata requests. It does not disable TLS verification or change the instance metadata configuration.

Test a known intended or unintended profile with an explicit expected result:

```bash
python audit.py metadata \
  --context 'test-vsi / isolated negative-control container / uid 1000' \
  --profile-id 'Profile-REPLACE_WITH_IN_SCOPE_PROFILE' \
  --expect-profile denied \
  --out output/profile-negative-control
```

Use a separate run with `--expect-profile allowed` for the positive control. To test a specific downstream read, add `--verify-instance 'INSTANCE_ID' --region us-south`. That performs only a GET of the selected instance using the issued profile token. A successful token exchange alone does not establish access to resources. HTTP 403 is recorded as refusal, not proof of its cause; timeouts, 401 and other errors are inconclusive. Initialization/user data, SSH keys, certificates and secrets are not collected by the metadata command.

See [ENGAGEMENT.md](ENGAGEMENT.md) for interpretation, further attack vectors and a report narrative template. The current implementation targets IBM VPC metadata, not PowerVS or bare-metal metadata.

## Validation and exit status

```bash
python -m unittest discover -s tests -v
```

Tests mock network operations and use invented identities, policies and tokens. They exercise the full demo/report workflow, IAM policy normalization, group inheritance, partial collection, pagination, redaction and metadata positive/negative outcomes. No cloud credentials are needed.

Exit `0` means the selected operation completed; findings can still be present. Exit `2` indicates invalid arguments or a collection/probe failure. Coverage limitations remain explicit even after exit `0`. Live IBM compatibility has not been validated in an account.
