# Research sources

Reviewed on 2026-10-12. Public web search and `cloud.ibm.com` documentation-page retrieval were attempted but returned proxy HTTP 403 in this development environment. Research therefore used IBM's official public GitHub documentation and SDK source. No search-engine result review or live-account validation is claimed.

The following sources support the implementation and manual test plan:

| Source | Used for |
| --- | --- |
| [IAM Identity Python SDK](https://github.com/IBM/platform-services-python-sdk/blob/main/ibm_platform_services/iam_identity_v1.py) | Service-ID groups, service IDs, key metadata, trusted profiles, claim rules, links, identities, account settings and pagination |
| [IAM Policy Management Python SDK](https://github.com/IBM/platform-services-python-sdk/blob/main/ibm_platform_services/iam_policy_management_v1.py) | IAM v1/v2 schemas, policy filters, visibility limitations and pagination |
| [IAM Access Groups Python SDK](https://github.com/IBM/platform-services-python-sdk/blob/main/ibm_platform_services/iam_access_groups_v2.py) | Group inventory, membership, dynamic rules and limited caller visibility |
| [Creating trusted profiles](https://github.com/ibm-cloud-docs/iam/blob/77f5fb2e87466c881c6f7f1dfed846f61131dec5/trustedprofile-create.md) | Compute, SAML, service-ID and service trust; future matching resources and explicit links |
| [Compute trusted-profile tutorial](https://github.com/ibm-cloud-docs/iam/blob/77f5fb2e87466c881c6f7f1dfed846f61131dec5/trustedprofile-compute-tutorial.md) | Kubernetes namespace/service-account trust behavior |
| [Service-to-service authorizations](https://github.com/ibm-cloud-docs/iam/blob/77f5fb2e87466c881c6f7f1dfed846f61131dec5/iam-authorizations.md) | Source/target scoping, external source accounts, dependent-service delegation |
| [Access-group dynamic rules](https://github.com/ibm-cloud-docs/iam/blob/77f5fb2e87466c881c6f7f1dfed846f61131dec5/iam-accessgroup_rules.md) | Federation claims, all-condition matching and account membership |
| [Context-based restrictions](https://github.com/ibm-cloud-docs/iam/blob/77f5fb2e87466c881c6f7f1dfed846f61131dec5/context-restrictions-what-is.md) | Network/endpoint controls, service support, report-only versus enforcement |
| [Cross-account restrictions](https://github.com/ibm-cloud-docs/account/blob/9e5a36ee32ba8cacf1f4258907bd0c113d6febf2/iam-cross-acct-restriction.md) | Resource-account allowlists, report-only decisions and audit events |
| [Metadata security practices](https://github.com/ibm-cloud-docs/vpc/blob/4133e597cc1515f14d55fb5c5b72580482c1aa8d/instance_metadata_vpc_security_bp.md) | HTTPS, local process access, host firewall controls, hop limits and profile minimization |
| [Metadata identity operations](https://github.com/ibm-cloud-docs/vpc/blob/4133e597cc1515f14d55fb5c5b72580482c1aa8d/instance_metadata_vpc_identity_operations.md) | Identity-token PUT, metadata header, lifetime and explicit-profile IAM-token exchange |
| [Metadata access](https://github.com/ibm-cloud-docs/vpc/blob/4133e597cc1515f14d55fb5c5b72580482c1aa8d/instance_metadata_vpc_access_instance_metadata.md) | Instance metadata GET, regional VPC configuration and sensitive initialization data |
| [Identity endpoint migration](https://github.com/ibm-cloud-docs/vpc/blob/4133e597cc1515f14d55fb5c5b72580482c1aa8d/metadata-identity-migration.md) | Current `/identity/v1/token` and `/identity/v1/iam_tokens` paths replacing legacy paths |

The live VPC and metadata requests pin API version `2025-10-14`. Review IBM's change logs and current service documentation before expanding the supported API surface. Synthetic fixtures model selected documented response shapes; they are not an IBM compatibility certification.
