# Contributing to Nito Core

Contributions include bug reports, testing, code review, documentation,
translations and patches. Use the
[issues](https://github.com/NitoNetwork/Nito-core/issues) and
[pull requests](https://github.com/NitoNetwork/Nito-core/pulls) of the official
repository for daemon, wallet and Qt changes. Base V4 work on `v4.0` and select
that branch as the pull request target; the default branch remains V3.

## Getting started

Read the [documentation index](doc/README.md), the
[developer notes](doc/developer-notes.md) and the
[validation guide](doc/nito/testing-validation.md). Choose a build guide for
your platform and run the tests relevant to the component you plan to change.

For a bug report, include the version or commit, operating system, steps to
reproduce, expected behavior and observed behavior. Remove recovery phrases,
private keys, RPC credentials and personal information from logs before sharing
them. Never attach a wallet file to a public issue.

Discuss substantial design changes in an issue before implementing them. A
consensus proposal should describe the rules, compatibility impact, activation
plan and evidence needed to evaluate it. Review the existing
[activation contract](doc/nito/consensus-activation.md) and
[wallet recovery contract](doc/nito/wallet-backup-restore.md) when working in
those areas.

## Preparing a patch

1. Fork the repository and create a topic branch from the target branch.
2. Keep the change focused. Separate unrelated formatting, file moves and
   behavior changes so reviewers can assess each one.
3. Add or update tests that demonstrate the behavior being changed. A bug fix
   should include a regression test when practical.
4. Update affected help text, documentation and translations.
5. Run the relevant checks and record the exact commands and results.
6. Commit the change, push your branch and open a pull request.

Use a short, descriptive commit subject with a component prefix, such as
`wallet: Preserve restore progress after restart`. Explain the problem and the
reason for the change in the body when the subject alone is insufficient. Keep
commits independently buildable where practical, and retain upstream copyright
and license notices.

Follow the [functional test conventions](test/functional/README.md) when adding
Python tests and the [translation process](doc/translation_process.md) for Qt
strings. Do not edit generated translation binaries directly.

## Pull requests

Describe the concrete problem, the resulting behavior and the validation
performed. Include a small before/after example when it makes the change easier
to assess. Identify any compatibility changes, untested platforms or remaining
limitations. Link related issues without copying their full discussion.

Use a draft pull request while work is incomplete. Respond to review feedback
in the existing pull request, including an explanation when you disagree with a
suggestion. After rebasing or changing the patch, state which tests were rerun
and which commit they cover.

Consensus, cryptography, wallet recovery and on-disk format changes need careful
review of failure paths as well as normal operation. Relevant cases can include
restart, reorganization, interrupted writes, pruning, locked wallets and older
wallet files. Preserve existing compatibility guarantees unless the proposal
explicitly changes them and explains the migration path.

## Code review

Anyone may review a change. Explain what you inspected and tested, and identify
the exact commit. Distinguish source review from execution evidence: an
inspection alone does not establish that a test or platform passed.

An approval should state its scope. For example, a reviewer can confirm a
specific regression test, review a subsystem, or test a packaged application on
one operating system. A concern should explain its impact and, where possible,
give a reproducer or a concrete alternative.

Maintainers decide whether a change is ready to merge based on its purpose,
correctness, compatibility, review and validation. Code changes and the
documentation describing them should remain consistent throughout review.
