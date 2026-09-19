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

## Cait Local Bridge current state

Before its first public release, Cait Local Bridge has 0 public dependents, 0 public package downloads, 0 external merged contributors and no meaningful OpenSSF criticality score. Those values should change only through real publication, use and contribution.

Use scripts/contributor-metrics.py for the rolling external-PR count after publication and scripts/oss-health.py for auditable health signals. If an upstream API does not expose a reliable metric, report unavailable rather than inventing a number.

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
