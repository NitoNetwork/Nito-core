# Nito Signet tools

Signet is a separate test chain whose blocks require Nito proof of work and a
signature satisfying the configured `signetchallenge`. Participants must use
the same challenge. For ordinary community testing, use the
[testnet guide](../../doc/nito/community-testnet.md). Test coins have no value.

## Mining

Run `nitod -signet` with your signing challenge configured and load a wallet
containing the keys and scripts needed to satisfy it. The miner obtains a block
template, asks the wallet to sign a PSBT, adds the solution to the coinbase,
finds proof of work and submits the completed block.

From a source build with Python 3 available:

```bash
CLI="./src/nito-cli -conf=/absolute/path/to/signet.conf"
MINER="./contrib/signet/miner"
GRIND="./src/nito-util grind"
ADDR=$($CLI -signet getnewaddress)
$MINER --cli="$CLI" generate --grind-cmd="$GRIND" --address="$ADDR" --min-nbits
```

These examples use paths without spaces. Use `--cli` before the subcommand.
Add `--ongoing` to keep mining, or
`--max-blocks=N` to stop after N blocks.

`--min-nbits` targets Signet's easiest permitted difficulty, `1e0fffff`.
`--nbits=<8 hex digits>` selects another desired target. These options steer
block timestamps; they do not override consensus difficulty. Nito adjusts
difficulty every block using a damped 60-second target. The first blocks can
therefore require substantially more work than the desired target.

Use `calibrate --grind-cmd="$GRIND" --seconds=25` to estimate a target for your
hardware. `--set-block-time=<Unix timestamp>` sets the time for a single block
and does not require `--nbits`; the node's timestamp rules still apply.

Other options include `--poisson` for variable intervals, `--multiminer=1/3`
for the first of three cooperating miners, and `--backup-delay` or
`--standby-delay` for backups. `--max-interval` must be at least 300 seconds.
Run `generate --help` for all options.

## Separate signing stages

The `genpsbt` and `solvepsbt` subcommands expose the signing pipeline. When
calling `walletprocesspsbt` yourself, specify `ALL`, matching the stored sighash:

```bash
$CLI -signet getblocktemplate '{"rules":["signet","segwit"]}' |
  $MINER --cli="$CLI" genpsbt --address="$ADDR" |
  { IFS= read -r psbt; printf '%s\ntrue\nALL\n' "$psbt"; } |
  $CLI -signet -stdin walletprocesspsbt |
  jq -r .psbt |
  $MINER --cli="$CLI" solvepsbt --grind-cmd="$GRIND" |
  $CLI -signet -stdin submitblock
```

## Test coins

`getcoins.py` requires Python's `requests` package and an explicit `--faucet`
URL supplied by your Nito Signet operator. It has no default public faucet.
Bitcoin Signet faucets do not supply Nito coins. The endpoint must accept the
request fields implemented by this script.

Use `--addr` to supply a receive address or `--cmd` to select `nito-cli`.
Use `--captcha` only if your operator provides a captcha endpoint; image
rendering requires ImageMagick. Run `getcoins.py --help` for all options.

## Tests

`feature_signet.py` checks a mined Nito block against matching and different
signing challenges and verifies peer synchronization. `tool_signet_miner.py`
rebuilds and signs that block through the miner's command line before reusing
its verified nonce. The node still validates the complete proof of work and
signature, while routine tests avoid a fresh difficulty-one search.
