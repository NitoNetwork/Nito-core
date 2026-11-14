# License And Third-Party Code

Nito Core is distributed under the MIT license. The authoritative text is in
[LICENSE](../../LICENSE) and [COPYING](../../COPYING). The software is provided
without warranty.

Nito Core derives from Bitcoin Core and includes third-party components. Their
source headers, package metadata, copyright notices and license files remain
authoritative for those components. The Nito Core MIT license does not replace
their terms.

Release packages include the applicable notices. The matching source archive,
dependency sources and redistribution instructions are described in
[release-sources.md](../release-sources.md).

## Orchard Cryptography

Nito Core v4 uses upstream Orchard cryptographic crates through
`src/private/orchard_ffi`:

| Dependency | Version | License |
| --- | --- | --- |
| `orchard` | `0.15.0` | MIT OR Apache-2.0 |
| `halo2_gadgets` | `0.5.0` | MIT OR Apache-2.0 |
| `zcash_note_encryption` | `0.4.1` | MIT OR Apache-2.0 |
| `incrementalmerkletree` | `0.8.2` | MIT OR Apache-2.0 |

The complete locked dependency set is recorded in
`src/private/orchard_ffi/Cargo.lock`. Nito explicitly selects its Orchard
bundle and circuit version; a dependency update cannot activate a different
consensus version by itself.

## Wallet And Graphical Dependencies

Official v4 builds retain Berkeley DB 4.8.30 so supported v3 legacy wallet
files can be opened directly. New descriptor wallets use SQLite.

Qt and other bundled libraries retain their respective licenses. Portable
archives place `LICENSE.txt` and the consolidated
`THIRD_PARTY_LICENSES.txt` beside the binaries. The Windows installer places
the same files in the installation directory, and the macOS application keeps
them in `Contents/Resources/`.
