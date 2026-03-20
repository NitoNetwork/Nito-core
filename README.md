# Nito Core

![imagenito](https://github.com/user-attachments/assets/41389ade-1a8e-4b9b-9f3a-2572bd1aadbb)

Nito Core connects to the Nito peer-to-peer network to download and fully validate blocks and transactions. It also includes a wallet and graphical user interface, which can be optionally built.

- **Releases:** [https://github.com/NitoNetwork/Nito-core/releases](https://github.com/NitoNetwork/Nito-core/releases)

Contact: help@nito.network

---

## Installation from Binaries

### Linux

```bash
# Download and extract
tar -xzf nito-*-x86_64-linux-gnu.tar.gz

# Install
sudo cp nito-*/bin/* /usr/local/bin/

# Create config
mkdir -p ~/.nito
cat > ~/.nito/nito.conf << EOF
server=1
daemon=1
rpcuser=nitorpc
rpcpassword=$(openssl rand -hex 32)
rpcallowip=127.0.0.1
EOF

# Start
nitod
```

### Windows

1. Download `nito-*-win64-setup.exe`
2. Run the installer
3. Launch Nito-Qt from Start Menu

### macOS

```bash
unzip nito-*-arm64-apple-darwin-tar.zip
tar -xzf nito-*-arm64-apple-darwin.tar.gz
sudo cp nito-*/bin/* /usr/local/bin/
```

---

## Building from Source

### Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils python3 libssl-dev libevent-dev libboost-all-dev \
    libsqlite3-dev libminiupnpc-dev libnatpmp-dev libzmq3-dev \
    libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools \
    libqrencode-dev libdb-dev libdb++-dev
```

**macOS:**
```bash
brew install automake libtool pkg-config boost libevent zeromq qt@5 miniupnpc libnatpmp qrencode berkeley-db@5
```

### Build

```bash
git clone https://github.com/NitoNetwork/Nito-core.git
cd Nito-core
./autogen.sh
./configure --with-gui=qt5 --with-incompatible-bdb
make -j$(nproc)
sudo make install
```

### Build without GUI

```bash
./configure --without-gui --with-incompatible-bdb
make -j$(nproc)
```

### Cross-Compile for Windows

```bash
sudo apt-get install -y g++-mingw-w64-x86-64
cd depends && make HOST=x86_64-w64-mingw32 -j$(nproc) && cd ..
./autogen.sh
./configure --prefix=$PWD/depends/x86_64-w64-mingw32 --host=x86_64-w64-mingw32
make -j$(nproc)
```

### Cross-Compile for ARM64

```bash
sudo apt-get install -y g++-aarch64-linux-gnu
cd depends && make HOST=aarch64-linux-gnu -j$(nproc) && cd ..
./autogen.sh
./configure --prefix=$PWD/depends/aarch64-linux-gnu --host=aarch64-linux-gnu
make -j$(nproc)
```

---

## Nito FAQ

| Parameter | Value |
|-----------|-------|
| **Launch Date** | Wednesday, August 21, 2024 |
| **Genesis Block** | "Nito/Core Genesis 8-4" |
| **Algorithm** | SHA256 |
| **Block Interval** | 60 Seconds |
| **Difficulty Adjustment** | Each new block |
| **P2P Port** | 8820 |
| **RPC Port** | 8821 |

---

## Supply Schedule

**Max Total Supply:** 1,284,565,890 NITO in ±200 Years

| Period | Block Reward | Block Range | Emitted | Total |
|--------|--------------|-------------|---------|-------|
| Year 1 | 512 → 256 | 0 - 530,000 | 271,359,488 | 271,359,488 |
| Year 2 | 256 → 128 | 530,001 - 1,042,400 | 131,174,400 | 402,533,888 |
| Year 3 | 128 → 64 | 1,042,401 - 1,576,800 | 68,403,200 | 470,937,088 |
| Years 4-10 | 64 → 32 | 1,576,801 - 5,256,000 | 235,468,800 | 706,405,888 |
| Years 11-20 | 32 → 16 | 5,256,001 - 10,512,000 | 168,192,000 | 874,597,888 |
| Years 21-50 | 16 → 2 | 10,512,001 - 26,280,000 | 252,288,000 | 1,126,885,888 |
| Years 51-200 | 2 → 0 | 26,280,001 - 105,120,001 | 157,680,002 | 1,284,565,890 |
| Years 201+ | 0 | 105,120,001+ | 0 | 1,284,565,890 |

*Or soft fork to maintain 1 NITO per block from year 201*

---

## Resources

- **Website:** [https://nito.network](https://nito.network)
- **Explorer:** [https://explorer.nito.network](https://explorer.nito.network)
- **Easy Node:** [https://nito.network/tools/easynode/](https://nito.network/tools/easynode/)

---

## License

Nito Core is released under the terms of the MIT license. See [COPYING](COPYING) for more information or see [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT).
