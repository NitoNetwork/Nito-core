Repository Tools
---------------------

> **Nito Core v4 release verification:** the inherited Guix/GPG
> `SHA256SUMS.asc` tooling below is not the official v4 release path. Verify v4
> downloads with `SHA256SUMS`, the detached Minisign signature and constrained
> GitHub provenance as documented in the repository
> [README](/README.md#download-and-verify).

### [Developer tools](/contrib/devtools) ###
Specific tools for developers working on this repository.
Additional upstream tools, including the `github-merge.py` script, are available in the [Bitcoin Core maintainer-tools](https://github.com/bitcoin-core/bitcoin-maintainer-tools) repository.

### [Verify-Commits](/contrib/verify-commits) ###
Tool to verify that every merge commit was signed by a developer using the `github-merge.py` script.

### [Linearize](/contrib/linearize) ###
Construct a linear, no-fork, best version of the blockchain.

### [Qos](/contrib/qos) ###

A Linux bash script that will set up traffic control (tc) to limit the outgoing bandwidth for connections to the Nito network. This means one can have an always-on nitod instance running, and another local nitod/nito-qt instance which connects to this node and receives blocks from it.

### [Seeds](/contrib/seeds) ###
Utility to generate the pnSeed[] array that is compiled into the client.

Build Tools and Keys
---------------------

### Packaging ###
The [Debian](/contrib/debian) subfolder contains the copyright file.

Nito release packaging is documented in the [release process](../doc/release-process.md).
The [Bitcoin Core packaging repository](https://github.com/bitcoin-core/packaging)
contains upstream distribution-specific examples.

### [MacDeploy](/contrib/macdeploy) ###
Scripts and notes for Mac builds.

Test and Verify Tools
---------------------

### [TestGen](/contrib/testgen) ###
Utilities to generate test vectors for the data-driven Nito tests.

### [Verify-Binaries](/contrib/verify-binaries) ###
Legacy GPG verification tooling. For Nito downloads, use the current
[checksum and manifest verification instructions](../README.md#download-and-verify).

Command Line Tools
---------------------

### [Completions](/contrib/completions) ###
Shell completions for bash and fish.
