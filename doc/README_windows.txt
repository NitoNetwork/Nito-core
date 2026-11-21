Nito Core for Windows
=====================

Extract the release archive and open bin\nito-qt.exe. For command-line use,
bin\nitod.exe runs the node and bin\nito-cli.exe sends local RPC commands.
If you used the installer, nito-qt.exe is in the installation directory and
the command-line tools are under daemon\ instead. The installer includes
nito-cli, nito-tx, nito-wallet and nito-util alongside nitod.

On first start, choose a data directory with enough free space for the chain,
wallets and indexes. Initial synchronization downloads and verifies blocks;
index construction can continue after those blocks have been downloaded.
Pruning reduces retained block data, but indexes and wallets use additional space.

Back up existing wallets before upgrading. Keep recovery phrases and wallet
backups private. A recovery phrase does not replace a wallet-file backup for
imported keys or every wallet's metadata.

V4 supports transparent transactions and Orchard private transactions.
Orchard availability depends on activation on the selected network and on
the local Orchard index being ready. Opening an encrypted wallet asks for its
passphrase, then keeps spending locked while the authenticated Qt session can
display wallet data. Each Bech32x address creation or send that requires
private keys asks for the passphrase again.

Licenses and matching source:
Portable archives contain only bin\ at their root. LICENSE.txt and
THIRD_PARTY_LICENSES.txt are inside bin\ with the executables.
The installer places the same two files in the installation directory.
Matching source and dependency-source instructions are available in the
repository at doc/release-sources.md. The detailed corresponding-source bundle
is retained as release-workflow evidence rather than attached as a public
release download.

Documentation and source:
https://github.com/NitoNetwork/Nito-core
https://github.com/NitoNetwork/Nito-core/blob/main/doc/nito/bech32x-private-wallet.md
