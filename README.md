# makefun-coin-launch-01

Zero-dependency pump.fun "ghost" token launcher (TypeScript, Node 22+).
Uses the current pump.fun `create_v2` instruction (Token-2022 mint, no MPL
metadata account) — verified against the official @pump-fun/pump-sdk 4.3.1
IDL, a live mainnet CreateV2 transaction, and a mainnet simulation.

## What it does
Downloads the official make.fun press kit, extracts the unmodified ghost
mascot (`mark-1024.png`), uploads token metadata, and builds + signs a
pump.fun CreateV2 transaction ready for broadcast.

Token: name `MakeFun Ghost`, symbol `GHOST`, description contains exactly
`made for make.fun $1000 bounty`.

## Requirements
- Node.js >= 22
- A funded wallet keypair at `LAUNCH_KEYPAIR_PATH` (JSON array of 64 bytes or 32-byte seed)
- ~0.01 SOL for fees (see Fee below)

## Usage
```bash
# Dry-run (build + sign, no broadcast)
LAUNCH_KEYPAIR_PATH=/path/to/keypair.json node --experimental-strip-types main.ts --dry-run

# Self-test (offline, no network, no keypair needed)
node --experimental-strip-types main.ts --self-test

# Live launch (requires network, wallet must have ~0.01 SOL)
LAUNCH_KEYPAIR_PATH=/path/to/keypair.json node --experimental-strip-types main.ts

# If pump.fun's IPFS upload is Cloudflare-blocked from your network,
# pre-upload the metadata (e.g. via browser) and pass its URI:
METADATA_URI=https://ipfs.io/ipfs/<cid> LAUNCH_KEYPAIR_PATH=/path/to/keypair.json node --experimental-strip-types main.ts --dry-run
```

## Fee
CreateV2 has **no 0.02 SOL program fee**. Measured from a live mainnet
CreateV2 tx: mint rent 2,722,880 + bonding-curve ATA rent 1,513,840 =
4,236,720 lamports + 10,000 tx fee. The launcher budgets
5,000,000 + 10,000 = **5,010,000 lamports (0.00501 SOL)** with margin.
Funding gate: **0.01 SOL**.

## Status
**NOT LAUNCHED** — Wallet `7CJfzRKxYiWiurqNMA5QVkq7z2fce35x4K1DWKhtx68E` has 0 SOL.
Needs ~0.01 SOL funding before a real launch.

## Caveats
- `https://pump.fun/api/ipfs` is Cloudflare-gated against server-side
  requests from some networks (HTTP 403). Use `METADATA_URI` to skip the
  upload, or run from a non-blocked network.
- Ghost logo is the press-kit's `mark-1024.png` (the make.fun ghost mark),
  used unmodified. Fallbacks: `icon-1024.png`, then `avatar-500.png`.

## Output
On successful live launch: writes `LAUNCH.json` with mint + signature.
Dry-run does not write `LAUNCH.json`.
