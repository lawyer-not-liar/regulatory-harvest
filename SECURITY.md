# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/lawyer-not-liar/regulatory-harvest/security/advisories/new). Private vulnerability reporting is enabled for this repository and routes reports to its maintainers.

Include the affected version, impact, and a minimal synthetic reproduction when possible. Do not include credentials, client or matter documents, personal information, or unrelated private files. Do not publish exploit details in a public issue. This experimental project does not promise a response-time or remediation service level.

## Security model

Regulatory Harvest processes untrusted documents and may contact user-supplied URLs or optional providers. It is a local research tool, not a hardened multi-tenant service.

### Source fetching

The built-in fetcher:

- accepts local files and explicit HTTP or HTTPS URLs;
- rejects URL credentials and non-HTTP schemes;
- resolves hosts and rejects non-global, private, loopback, link-local, multicast, reserved, and unspecified addresses;
- revalidates each redirect target;
- limits redirects, response time, and downloaded bytes;
- treats HTML as text and removes executable or hidden elements before normalization.

These controls reduce SSRF and resource-exhaustion risk but do not eliminate it. DNS can change between validation and connection, proxies can alter routing, and a public address can front a service with access to internal systems. Do not process attacker-controlled URLs from a privileged network without an egress proxy, network isolation, or a fetch service that pins validated destinations.

### Local files and PDFs

Local source paths are explicitly supplied by the user. Relative paths are resolved against the request file directory. Symlinks and `..` components can reach files outside that directory, so do not run untrusted request files with access to sensitive files.

Downloads are byte-limited, but compressed or malformed PDFs can still consume disproportionate CPU or memory in a parser. The dependency-free skill runtime refuses direct PDF normalization; use a verified UTF-8 extraction and record that limitation. When using the full package's PDF path, process high-risk files in an isolated, resource-limited environment and keep `pypdf` current.

### Artifact storage

The filesystem store rejects absolute artifact names, traversal components, and unsafe run identifiers. Writes use a sibling temporary file, `fsync`, and atomic replacement. Run locks prevent ordinary concurrent writers. `--clear-stale-lock` can override that protection and must be used only after confirming no writer remains active.

Output directories and their contents may contain complete normalized legal source text. Apply filesystem permissions, encryption, retention, backup, and matter-access controls appropriate to the material. Regulatory Harvest provides none of those controls itself.

### Optional providers and secrets

Reference adapters read `OPENAI_API_KEY` or `TAVILY_API_KEY` only when instantiated without an explicit client or key. Credentials are sent in provider authentication, not serialized in requests, fingerprints, bundles, reports, or safe provider errors.

Using a provider sends documented research context or normalized excerpts outside the local machine. Confirm client authorization, provider terms, data residency, retention, and professional-responsibility requirements before enabling one. The OpenAI adapter sets `store=False`, but that parameter is not a substitute for reviewing applicable provider policies.

### Release scanning

Before building a release, run `uv run python scripts/audit_release.py --json`. It inspects tracked text for common credential formats and other clean-room hazards without printing matched values. A clean result does not prove that secrets are absent: encoded credentials, unfamiliar token formats, binary files, deleted Git history, and external build inputs require separate review. Use hosting-provider secret scanning when a public remote is authorized, and rotate any credential that may have entered the working tree or history.

The audit's `MANUAL_CONFIRMATION_REQUIRED` item is intentional. Automated checks cannot authorize disclosure or publication. See [the release checklist](docs/release-checklist.md) before creating a public remote.

### Reports and imported bundles

The Markdown renderer escapes untrusted metadata, reduces local paths to file names, removes URL userinfo/query/fragment material, filters provider metadata, and does not render raw fetch or provider exception messages. Treat imported bundles as untrusted data and render Markdown only in viewers with scripting disabled.

## Supported versions

| Version | Security maintenance |
| --- | --- |
| Latest published `0.1.0-beta.*` prerelease | Current experimental maintenance target; fixes may require upgrading to a newer prerelease. |
| Earlier, superseded prereleases | No separate backports; upgrade to the latest prerelease. |
| Unreleased `main` | Development only; not a published release or a stability guarantee. |

No stable release is currently supported. Experimental status does not remove the requirement for attorney review or justify bypassing integrity failures.
