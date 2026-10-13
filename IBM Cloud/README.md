# IBM Cloud IAM service-to-service audit

Python 3.10+; standard library only. No Python package installation is needed. CLI authentication additionally requires the IBM Cloud CLI and an existing login.

The standalone `audit.py` script collects IAM configuration, correlates workload identities with grants, and writes an engagement-style transcript that can be displayed with `cat`. Copy this one Python file to the machine where you will run the audit; no other source files are required. You run the commands in your own account.

## Commands and report output

From the repository root:

```bash
cd 'IBM Cloud'
python audit.py --help
python audit.py scan --help
python audit.py metadata --help
```

Use `scan` for the account review and `metadata` for a selected local workload, as described below. Use a new output path for each run; the tool refuses to overwrite an existing directory. After running an account review, display its terminal-style report with `cat output/account-review/transcript.txt`.

Each run produces:

| File | Purpose |
| --- | --- |
| `transcript.txt` | Terminal-style requests, responses, timestamps, tester review narrative, findings and coverage gaps |
| `report.json` | Redacted collected inventory, request events and structured findings |
| `SHA256SUMS.json` | SHA-256 hashes of both evidence files; useful for detecting accidental changes, not a signed attestation |

The displayed `curl` commands are readable equivalents of Python HTTP requests. Python executes the requests; the transcript is not a claim that someone typed `curl`. In reports, “the tester reviewed” describes automated rule evaluation; the report still needs human validation. Credentials and token fields are redacted. Account IDs, resource names, memberships and policies remain in evidence, so review files before sharing. Output is excluded from Git.

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

To reuse your existing `ibmcloud` login, as in the original CLI-based collector:

```bash
ibmcloud target
python audit.py scan --auth cli --region us-south --out output/account-review
cat output/account-review/transcript.txt
```

If you need to sign in first, run `ibmcloud login` (or `ibmcloud login --sso` for SSO), then select your account with `ibmcloud target -c ACCOUNT_ID`. These are actions you perform locally; the collector never starts an interactive login or changes your CLI target/region. With CLI authentication, `--account-id` or `ACCOUNT_ID` is an optional expected account: if supplied, it must match the current target. If omitted, the targeted account is used.

The collector obtains the session's IAM token using `ibmcloud iam bearer-token`, with `ibmcloud iam oauth-tokens` as a compatibility fallback for older CLI versions. CLI authentication output is never written to the transcript or JSON evidence; only the command and exit status are recorded. The token is held in memory and used for the existing REST collection. This adds CLI-session authentication; it does not replace collection with the commands from your previous script. Use `--cli /path/to/ibmcloud` if needed.

Authentication selection is explicit:

| Option | Behavior |
| --- | --- |
| `--auth cli` | Use the current CLI session even if an API-key environment variable is set |
| `--auth api-key` | Require an API key and `ACCOUNT_ID` or `--account-id` |
| `--auth auto` (default) | Use an API key if present; otherwise use the CLI session |

There is no switch to a different authentication identity after failure. If an old or unwanted API key is exported while your CLI session works, choose `--auth cli`.

For API-key authentication, supply the key in your own shell without placing its value in command history:

```bash
read -r -s -p 'IBM Cloud API key: ' IBMCLOUD_API_KEY
export IBMCLOUD_API_KEY
export ACCOUNT_ID='YOUR_32_CHARACTER_ACCOUNT_ID'
python audit.py scan --auth api-key --region us-south --region eu-gb --out output/account-review
unset IBMCLOUD_API_KEY
cat output/account-review/transcript.txt
```

Use a session or key scoped to the intended account. Regional VPC calls are skipped with a collection error unless the IAM-issued token's account context matches the selected account. This context check is not an independent JWT signature validation. `--account-id` overrides `ACCOUNT_ID`; `IBM_CLOUD_API_KEY` is also accepted for API-key authentication. Omit `--region` for an IAM-only review. The default key-age review threshold is 90 days; change it with `--key-age-days`. It is an engagement threshold, not an IBM-mandated limit.

The account scan issues GET requests after obtaining an IAM token from the CLI or exchanging the auditor's API key. It does not change policies, credentials or resource configuration. Required HTTPS destinations are `iam.cloud.ibm.com` and each selected `<region>.iaas.cloud.ibm.com`. TLS verification remains enabled, redirects are refused, and pagination is restricted to the original API origin and path. HTTP requests time out after 20 seconds; CLI authentication commands time out after 45 seconds. Rerun into a new evidence directory after resolving failures or rate limiting. Tokens are not refreshed automatically during long audits; expired-token failures are retained as coverage gaps.

If authentication fails, the script prints a specific failure before the evidence path. A later collection HTTP 403 is an authorization/visibility failure, not proof that login failed. Check which operation failed in `transcript.txt`; do not share token output from `ibmcloud iam bearer-token` or `oauth-tokens`.

## Test metadata from your IBM VPC workload

Run this command **inside the selected IBM VPC instance or container**, as the OS/workload identity whose access is being reviewed. The context label is supplied by you, not independently attested by the tool. No metadata requests are issued by `scan`.

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

## Offline checks and exit status

```bash
python -m py_compile audit.py
python audit.py --help
```

These commands check syntax and CLI loading without credentials or network requests. They do not validate access to IBM Cloud or the account's security posture.

Exit `0` means the selected operation completed; findings can still be present. Exit `2` indicates invalid arguments or a collection/probe failure. Coverage limitations remain explicit even after exit `0`. Live IBM compatibility has not been validated in an account.
