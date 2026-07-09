# AmigoTap NFC

Read and write **NDEF links** to MIFARE Classic 1K NFC tags using an
**ACS ACR122U** (or any PC/SC CCID reader) on macOS. Ships as both a
double-clickable **Mac app** and a command-line tool.

It exists because most desktop NFC apps fail to *NDEF-format* MIFARE Classic
tags: they write data but never write the MAD directory or change the sector
keys, so phones can't read the result. AmigoTap does the full format the way a
phone does, so tags it writes read on **both Android and iPhone**.

Language: the NFC engine is **C** (talks to macOS's built-in PC/SC framework);
the GUI is **Swift / AppKit**.

## The Mac app (recommended)

```sh
./build-app.sh       # produces "AmigoTap NFC.app" and AmigoTap-NFC.dmg
```

Open `AmigoTap-NFC.dmg`, drag **AmigoTap NFC** into Applications, done.
The app is ad-hoc signed (no Apple Developer account), so the **first** time you
open it: right-click the app → **Open** → **Open** to get past Gatekeeper.
After that it launches normally.

In the app: type a link, put a tag on the reader, click **Write to Tag**
(or **Read Tag** to see what's on a tag).

## The command-line tool

```sh
make                 # produces ./nfctag
make install         # optional: copies to /usr/local/bin
```

No dependencies — uses the macOS built-in PC/SC framework and CCID driver.

## Usage

```sh
./nfctag read                        # read & parse the tag on the reader
./nfctag write "https://example.com" # format if needed, then write a URI record
./nfctag write --text "hello"        # write a plain-text record
./nfctag dump                        # hex-dump every sector (with the key used)
```

Place a tag on the reader before running. Example:

```sh
./nfctag write "https://linktree-flax-chi.vercel.app/mobile-space"
```

Writing is **idempotent**: on a blank tag it formats (writes MAD + switches data
sectors to the NDEF key `D3F7D3F7D3F7`); on an already-formatted tag it just
rewrites the message.

## How it works (MIFARE Classic NDEF)

- **Sector 0** holds the **MAD** (MIFARE Application Directory). Every data
  sector is flagged with the NFC Forum AID `0x03E1`. Sector-0 trailer uses the
  MAD key `A0A1A2A3A4A5`, GPB `0xC1`.
- **Sectors 1–15** hold the NDEF message as a TLV (`03 <len> …message… FE`),
  laid out across the 3 data blocks of each sector (trailers skipped). Their
  trailers use Key A `D3F7D3F7D3F7`, access bits `7F 07 88`, GPB `0x40`,
  Key B `FFFFFFFF` (so the tag stays rewritable).
- URLs are compressed with the NFC Forum URI prefix table (e.g. `https://`
  becomes a single 0x04 byte).

## Notes / limits

- Targets MIFARE Classic **1K** (16 sectors). NTAG21x tags are already
  NDEF-formatted from the factory and work with phone apps directly.
- Max message on a 1K tag is ~700 bytes; plenty for links.
- A tag must be placed on the reader for each command.

## Files

- `nfctag.c` — the whole program
- `Makefile` — build/install/clean
