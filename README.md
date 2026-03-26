# Nito Core

![imagenito](https://github.com/user-attachments/assets/41389ade-1a8e-4b9b-9f3a-2572bd1aadbb)

Nito Core connects to the Nito peer-to-peer network to download and fully validate blocks and transactions. It also includes a wallet and graphical user interface, which can be optionally built.

- **Latest Release:** [Download](https://github.com/NitoNetwork/Nito-core/releases/latest)
- **Whitepaper:** [Nito Whitepaper v3.0](https://nitonetwork.github.io/Nito-Whitepaper/)

Contact: help@nito.network

---

## Installation from Binaries

Download the latest release for your platform from the [Releases](https://github.com/NitoNetwork/Nito-core/releases) page.

### Linux (x86_64 or ARM64)

```bash
# Download and extract (replace with correct filename)
tar -xzf nito-3.0.1-x86_64-linux-gnu.tar.gz

# Install binaries
sudo cp nito-3.0.1-x86_64-linux-gnu/bin/* /usr/local/bin/

# Create data directory and config
mkdir -p ~/.nito
cat > ~/.nito/nito.conf << EOF
server=1
daemon=1
rpcuser=nitorpc
rpcpassword=$(openssl rand -hex 32)
rpcallowip=127.0.0.1
EOF

# Start the daemon
nitod

# Or start the GUI wallet
nito-qt
```

### Windows

**Option A — Installer:**
1. Download `nito-3.0.1-win64-setup.exe`
2. Run the installer
3. Launch **Nito Core** from the Start Menu or Desktop shortcut

**Option B — Portable ZIP:**
1. Download `nito-3.0.1-win64.zip`
2. Extract to a folder of your choice
3. Run `nito-qt.exe` for the GUI wallet

### macOS

```bash
tar -xzf nito-3.0.1-x86_64-apple-darwin.tar.gz
sudo cp nito-3.0.1/bin/* /usr/local/bin/
nito-qt
```

---

## Verify Downloads (SHA256)

```
sha256sum nito-3.0.1-*.tar.gz nito-3.0.1-*.zip nito-3.0.1-*-setup.exe
```

Compare the output with the checksums listed on the [release page](https://github.com/NitoNetwork/Nito-core/releases/latest).

---

## Building from Source

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils python3 curl git bison
```

For cross-compilation (optional):
```bash
# Windows cross-compile
sudo apt-get install -y g++-mingw-w64-x86-64 nsis zip

# ARM64 cross-compile
sudo apt-get install -y g++-aarch64-linux-gnu binutils-aarch64-linux-gnu
```

**macOS:**
```bash
brew install automake libtool pkg-config
```

### Build with depends (recommended)

The `depends` system downloads and builds all dependencies locally, ensuring reproducible builds.

```bash
git clone https://github.com/NitoNetwork/Nito-core.git
cd Nito-core

# Download Qt sources (required for GUI)
mkdir -p depends/sources && cd depends/sources
curl -L -O https://download.qt.io/archive/qt/5.15/5.15.11/submodules/qtbase-everywhere-opensource-src-5.15.11.tar.xz
curl -L -O https://download.qt.io/archive/qt/5.15/5.15.11/submodules/qttranslations-everywhere-opensource-src-5.15.11.tar.xz
curl -L -O https://download.qt.io/archive/qt/5.15/5.15.11/submodules/qttools-everywhere-opensource-src-5.15.11.tar.xz
cd ../..

# Build dependencies
cd depends && make HOST=x86_64-pc-linux-gnu -j$(nproc) && cd ..

# Build Nito
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site \
    ./configure --prefix=/ --disable-tests --disable-bench
make -j$(nproc)
```

Binaries will be in `src/` (`nitod`, `nito-cli`, `nito-qt`, etc.)

### Build without GUI

```bash
cd depends && make HOST=x86_64-pc-linux-gnu NO_QT=1 -j$(nproc) && cd ..
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site \
    ./configure --prefix=/ --disable-tests --disable-bench
make -j$(nproc)
```

### Cross-Compile for Windows

```bash
cd depends && make HOST=x86_64-w64-mingw32 -j$(nproc) && cd ..
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site \
    ./configure --prefix=/ --disable-tests --disable-bench
make -j$(nproc)
```

### Cross-Compile for ARM64 (Raspberry Pi, ARM servers)

```bash
cd depends && make HOST=aarch64-linux-gnu -j$(nproc) && cd ..
./autogen.sh
CONFIG_SITE=$PWD/depends/aarch64-linux-gnu/share/config.site \
    ./configure --prefix=/ --disable-tests --disable-bench --enable-reduce-exports
make -j$(nproc)
```

---

## Nito Specifications

| Parameter | Value |
|-----------|-------|
| **Launch Date** | Wednesday, August 21, 2024 |
| **Genesis Block** | "Nito/Core Genesis 8-4" |
| **Algorithm** | SHA-256 (Proof-of-Work) |
| **Block Time** | 60 seconds |
| **Difficulty Adjustment** | Every block (damped retarget) |
| **Max Supply** | 1,284,565,890 NITO (~200 years) |
| **Smallest Unit** | 1 Nitoshi = 0.00000001 NITO |
| **P2P Port** | 8820 |
| **RPC Port** | 8821 |
| **Address Formats** | Bech32 (nito1...), Legacy, P2SH, Taproot (nito1p...) |

---

## Supply Schedule

| Period | Reward/Block | Block Range | Period Total | Cumulative |
|--------|-------------|-------------|-------------|------------|
| Year 1 | 512 | 0 - 529,999 | 271,359,488 | 271,359,488 |
| Year 2 | 256 | 530,000 - 1,042,399 | 131,174,400 | 402,533,888 |
| Year 3 | 128 | 1,042,400 - 1,576,799 | 68,403,200 | 470,937,088 |
| Years 4-10 | 64 | 1,576,800 - 5,255,999 | 235,468,800 | 706,405,888 |
| Years 11-20 | 32 | 5,256,000 - 10,511,999 | 168,192,000 | 874,597,888 |
| Years 21-50 | 16 → 2 | 10,512,000 - 26,279,999 | 252,288,000 | 1,126,885,888 |
| Years 51-200 | 2 → 0 | 26,280,000 - 105,120,000 | 157,680,002 | 1,284,565,890 |

---

## Resources

- **Website:** [https://nito.network](https://nito.network)
- **Explorer:** [https://explorer.nito.network](https://explorer.nito.network)
- **Whitepaper:** [https://nitonetwork.github.io/Nito-Whitepaper/](https://nitonetwork.github.io/Nito-Whitepaper/)
- **Easy Node:** [https://nito.network/tools/easynode/](https://nito.network/tools/easynode/)
- **Komodo Wallet (DEX):** [https://komodoplatform.com/](https://komodoplatform.com/)

---

## License

Nito Core is released under the terms of the MIT license. See [COPYING](COPYING) for more information or see [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT).
