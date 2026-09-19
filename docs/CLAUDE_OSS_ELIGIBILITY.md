# Claude for Open Source eligibility tracker

Status checked: 2026-09-19. This is a maintainer governance document, not product marketing.

Authoritative sources:
- https://www.anthropic.com/claude-for-oss-terms
- https://claude.com/contact-sales/claude-for-oss

## Current official Maintainer Track

Anthropic's current terms say an applicant may qualify if at least one Maintainer Track condition applies, or through the discretionary Ecosystem Impact Track, and all general eligibility requirements are met.

| Criterion | Threshold | Aggregation or window |
| --- | ---: | --- |
| Dependent repositories | >= 500 | maintained projects, aggregate |
| Dependent packages | >= 100 | maintained projects, aggregate |
| Monthly package downloads | >= 200,000 | maintained packages, aggregate monthly |
| Recognized foundation or language role | listed committer or maintainer | current role |
| PRs into repositories not owned by applicant | >= 100 merged | preceding 12 months |
| External contributors to a maintained repository | >= 20 unique people with merged PRs | one repository, preceding 12 months |
| OpenSSF criticality | >= 0.4 | a maintained repository |

The official page and terms currently state a six-month complimentary Claude Max 20x benefit. Applications are rolling until Anthropic closes the program or the recipient cap is reached. Criteria may change.

## General eligibility

The terms require a natural person of legal age, residence where Claude.ai is available and sanctions/export compliance; a GitHub account in good standing at least two years old; public OSS activity in the preceding 90 days; maintenance of or contribution to an OSI-approved project; and no disqualifying Anthropic employment or household relationship.

Machine-verifiable facts for this maintainer as of 2026-09-19:
- authenticated GitHub account: HanpuLi;
- GitHub account created 2019-11-01, satisfying the two-year account-age threshold;
- HanpuLi/liuzheng is public under MIT and has a public commit dated 2026-08-31, satisfying the observable license and recent-public-activity requirements if they remain current at application time.

Age, residence/sanctions and employment/household conditions are personal attestations and are not inferred by this repository.

## ScopeRail current state

The project became public under its former name on 2026-09-19 and published GitHub Release `v0.1.0` the same day. ScopeRail is the renamed public identity beginning with `v0.2.0`. The baseline below is evidence-driven: an unavailable metric is not silently converted to zero.

| Criterion | Current evidence | Threshold | Gap / status | Verification |
| --- | ---: | ---: | --- | --- |
| External contributors to this repository | 0 unique external merged-PR authors | 20 in one maintained repository / 12 months | 20 | `metrics/contributors.json` |
| Dependent repositories | unavailable | 500 aggregate across maintained projects | no qualifying evidence collected yet | `metrics/oss-health.json`; use a reliable dependency source when available |
| Dependent packages | unavailable | 100 aggregate across maintained projects | no qualifying evidence collected yet | `metrics/oss-health.json`; do not infer a count |
| Monthly package downloads | unavailable; PyPI package not yet published | 200,000 aggregate monthly | package publication and real adoption required | PyPI/PyPI Stats after publication |
| OpenSSF criticality | 0.12244 measured with OpenSSF `criticality_score` v2.0.4 using GitHub signals only (`deps.dev` disabled) | >= 0.4 for a maintained repository | measured shortfall 0.27756; the full deps.dev-enriched default score is still unavailable because Google Cloud ADC is not configured | `metrics/oss-health.json`; official OpenSSF CLI |
| General observable eligibility | GitHub account-age, recent public activity and OSI-license evidence present | all general requirements | personal attestations still apply | GitHub metadata plus applicant attestation |

The public repository also has live CI/security workflows, branch protection, private vulnerability reporting and a small set of independently useful contributor issues. Stars, forks and issue counts may be tracked as project-health context, but they are not substituted for Anthropic's qualifying metrics.

Use `scripts/contributor-metrics.py` for the rolling external-PR count and `scripts/oss-health.py` for auditable health signals. If an upstream API does not expose a reliable metric, report unavailable rather than inventing a number.

## Artificial activity is prohibited

Anthropic explicitly reserves the right to discount trivial, duplicative or automated activity and to disqualify applicants for artificially inflated dependents, downloads, contributions, reviews or contributor counts, including purchased engagement, exchange schemes, bots, contribution-graph padding and similar manipulation.

For this project:
- no self-dependent repo farms or meaningless packages;
- no repeated installs or download bots;
- no fake accounts, bot contributors or coordinated typo PRs;
- no purchased stars, forks or downloads;
- no issue or commit churn designed for OpenSSF scoring;
- no counting owner or bot PRs as external contributors.

Contributor issues exist to expose real independently useful work. Qualification, if it occurs, should be a consequence of adoption.
