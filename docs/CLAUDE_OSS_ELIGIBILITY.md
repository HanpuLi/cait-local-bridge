# Claude for Open Source eligibility tracker

Status checked: 2026-09-19. This is a maintainer governance document, not product marketing.

Authoritative sources:
- https://www.anthropic.com/claude-for-oss-terms
- https://claude.com/contact-sales/claude-for-oss

## Current official criteria

Anthropic's current terms say an applicant must meet at least one Maintainer Track criterion or qualify through the discretionary Ecosystem Impact Track, and must also satisfy all general eligibility requirements.

| Criterion | Threshold | Aggregation or window |
| --- | ---: | --- |
| Dependent repositories | >= 500 | maintained projects, aggregate |
| Dependent packages | >= 100 | maintained projects, aggregate |
| Monthly package downloads | >= 200,000 | maintained packages, aggregate monthly |
| Recognized foundation or language role | listed committer or maintainer | current role |
| PRs into public repositories not owned by applicant | >= 100 merged | preceding 12 months |
| External contributors to a maintained repository | >= 20 unique people with merged PRs | one repository, preceding 12 months |
| OpenSSF criticality | >= 0.4 | a maintained repository |

The program currently provides six months of complimentary Claude Max 20x. The terms state a recipient cap of 10,000 unless Anthropic increases it, and applications are rolling until the program closes or the cap is reached. Meeting a numeric threshold is a minimum for consideration, not a guarantee of acceptance.

Anthropic also states that trivial, duplicative, automated or artificially inflated activity may be discounted or lead to disqualification.

## General eligibility

The terms also require:
- a natural person of legal age;
- legal residence where Claude.ai is available and applicable sanctions/export compliance;
- a GitHub account in good standing that is at least two years old;
- public OSS contribution activity within the preceding 90 days;
- maintenance of or contribution to an OSI-approved open-source project; and
- no disqualifying Anthropic employment/contractor/agent or immediate-family/household relationship.

Machine-verifiable account facts are recorded in `metrics/claude-oss-account.json`. As of 2026-09-19, the GitHub account was created in 2019, has current public OSS activity and maintains multiple public repositories with detected OSI license metadata. Personal eligibility conditions still require applicant attestation.

## Account-level Maintainer Track baseline

The qualifying thresholds are account/project-ecosystem thresholds, so the primary baseline is now account-level rather than ScopeRail-only.

| Criterion | Current verified evidence | Threshold | Current status |
| --- | ---: | ---: | --- |
| Merged PRs into external public repositories | **0** | 100 / 12 months | not met |
| Merged PRs into owned repositories | 36 | excluded from the 100-PR criterion | context only |
| Highest unique external human contributors on one maintained repo | **0** | 20 / 12 months | not met |
| Highest measured OpenSSF criticality | **0.18142** — `HanpuLi/shepperton-spatial-audit` | 0.4 | not met |
| ScopeRail measured OpenSSF criticality | **0.13792** | 0.4 | not met |
| Dependent repositories | unavailable | 500 aggregate | no qualifying evidence collected |
| Dependent packages | unavailable | 100 aggregate | no qualifying evidence collected |
| Monthly package downloads | unavailable | 200,000 aggregate | no qualifying evidence collected |
| Recognized foundation/language maintainer role | requires applicant evidence | listed role | no machine-verifiable evidence asserted here |

The PR/contributor figures come from GitHub's public merged-PR data for the rolling 12-month window. Owner PRs and obvious bot accounts are excluded. The criticality values were measured on 2026-09-19 with OpenSSF `criticality_score` v2.0.4 using GitHub signals only and `deps.dev` disabled. They must **not** be represented as the full deps.dev-enriched default score.

All nine maintained public source repositories were measured. The highest GitHub-only score was 0.18142; no measured repository was close to the 0.4 threshold.

See:
- `metrics/claude-oss-account.json` — account-wide audit snapshot;
- `metrics/contributors.json` — ScopeRail external-contributor snapshot;
- `metrics/oss-health.json` — ScopeRail health/publication snapshot.

## ScopeRail publication state

ScopeRail is a real installable public project with tagged GitHub release artifacts and protected CI/security checks. The current health snapshot records four GitHub releases and a tested wheel installation path.

However, the first PyPI publication has not yet been completed, and the MCP Registry entry was not found in the 2026-09-19 public check. The release workflow is already prepared for:
1. PyPI Trusted Publishing using GitHub OIDC;
2. publication of the matching MCP Registry metadata only after the referenced PyPI package exists.

The remaining first-publication blocker is a one-time human PyPI trusted-publisher/account action. Credentials should never be handed to an automation or stored in the repository.

## What actually moves eligibility

There is no credible short-term path to a numeric Maintainer Track threshold by making more changes inside repositories owned by the applicant.

Useful next steps are instead:

1. **Finish distribution.** Complete the one-time PyPI Trusted Publisher setup for ScopeRail, then let the existing release workflow publish the exact GitHub release bytes to PyPI and the MCP Registry. This creates a real public dependency/download surface.
2. **Contribute externally.** Make substantive fixes/features to established public projects not owned by the applicant. Only merged external PRs count toward the 100-PR criterion.
3. **Earn external participation.** Make ScopeRail or another maintained project useful enough that independent people file, implement and merge real contributions. Do not manufacture contributor counts.
4. **Collect downstream evidence.** Track package downloads and dependency-graph dependents only after a public registry/package ecosystem can report them.
5. **Use the Ecosystem Impact Track only with evidence.** Anthropic permits discretionary applications below the numeric thresholds, but an application should point to genuine downstream use, infrastructure significance or adoption rather than repository polish alone.

## Artificial activity is prohibited

Do not:
- create self-dependent repository farms or meaningless packages;
- repeat installs/downloads to inflate registry counts;
- use fake accounts, bot contributors or coordinated trivial PRs;
- purchase stars, forks, downloads or engagement;
- churn issues/commits to influence OpenSSF signals;
- count owner or bot PRs as external contributors.

Qualification, if it occurs, should be a consequence of real ecosystem use and external contribution.
