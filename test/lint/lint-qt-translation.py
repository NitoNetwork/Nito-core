#!/usr/bin/env python3
#
# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
#
# Check for leading whitespaces in the translatable strings.

from pathlib import Path
import html
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


MOJIBAKE_PATTERNS = [
    # UTF-8 punctuation decoded as Windows-1252/Latin-1.
    "\u00e2\u20ac\u00a6",  # ...
    "\u00e2\u20ac\u2122",  # right apostrophe
    "\u00e2\u20ac\u0153",  # left quote
    "\u00e2\u20ac\u009d",  # right quote
    "\u00e2\u20ac\u201c",  # en dash
    "\u00e2\u20ac\u201d",  # em dash
    # Common Western accented letters decoded as Windows-1252/Latin-1.
    "\u00c3[\u00a0-\u00bf]",
    "\u00c2[\u00a0-\u00bf]",
    "\ufffd",
]

V4_TRANSLATION_GUARDS = [
    "Source address unavailable",
    "%1 input addresses",
    "Show input addresses",
    "Hide input addresses",
    "Some input addresses are unavailable.",
    "Wallet loading failed.",
    "Some blocks required for complete wallet recovery have been pruned. To reconstruct your wallet and its complete history, use a non-pruned node or perform a full resynchronization. This requires downloading data, time and disk space. No resynchronization has been started.",
    "The Orchard index cannot catch up because required blocks have been pruned. To recover Orchard functionality, use a non-pruned node or explicitly rebuild with -reindex and -prune=0. This requires downloading data, time and disk space. No resynchronization has been started. To continue without Orchard, restart with -orchardindex=0; private balances and spending will be unavailable.",
    "Warning: If you encrypt your wallet and lose your passphrase, you will <b>LOSE ALL OF YOUR NITO</b>!",
    "Are you sure you wish to encrypt your wallet?",
    "Remember that encrypting your wallet cannot fully protect your NITO from being stolen by malware infecting your computer.",
    "Wallet to be encrypted",
    "Your wallet is about to be encrypted. ",
    "This operation needs your wallet passphrase to unlock the wallet.",
    "Opening Wallet <b>%1</b>...",
    "Recent transactions may not yet be visible, and therefore your wallet's balance might be incorrect. This information will be correct once your wallet has finished synchronizing with the Nito network, as detailed below.",
    "Attempting to spend NITO affected by not-yet-displayed transactions will not be accepted by the network.",
    "Enable private Bech32x receiving addresses",
    "Show Bech32x private receiving addresses, private balances and private balance controls after the activation block.",
    "Spend Bech32x private notes. Leave unchecked to spend transparent UTXOs.",
    "Nito.network private transactions activate at block %1. Current block: %2.",
    "Nito.network private transactions are not active on this network.",
    "Bech32x (Orchard)",
    "Generates a Bech32x Orchard receiving address starting with nito1x.",
    "Funding source",
    "Private balance",
    "Transparent balance",
    "To review recipient list click \"Show Details...\"",
    "Show Details...",
    "Hide Details...",
    "Multiple recipients",
    "multiple recipients",
    "The private wallet index is not available. Restart Nito Core with private wallet indexing enabled (-orchardindex=1) before using Bech32x wallet features.",
    "Private receiving address metadata is not available yet for this encrypted wallet. Unlock the wallet once or restore it from the recovery phrase to prepare private receiving addresses.",
    "Recovery Phrase",
    "Show Recovery Phrase",
    "The recovery phrase controls the funds derived from its documented scope. Keep wallet.dat backups for V3 or imported transparent keys. Only reveal the phrase in a private place and store it offline.",
    "Write these words down in order. Anyone with this phrase can spend the funds it covers. A wallet upgraded from V3 still requires its wallet.dat backup for older transparent keys.",
    "Internal transfer",
    "own wallet",
]

FORBIDDEN_TRANSLATION_SOURCES = [
    "Warning: If you encrypt your wallet and lose your passphrase, you will <b>LOSE ALL OF YOUR NITOS</b>!",
    "Warning: If you encrypt your wallet and lose your passphrase, you will <b>LOSE ALL OF YOUR NITOSHI</b>!",
    "Remember that encrypting your wallet cannot fully protect your nitos from being stolen by malware infecting your computer.",
    "Loading wallets...",
    "Loading wallets…",
    "Loading wallets?",
    "Opening Wallet <b>%1</b>…",
    "Attempting to spend nitos that are affected by not-yet-displayed transactions will not be accepted by the network.",
    "Recent transactions may not yet be visible, and therefore your wallet's balance might be incorrect. This information will be correct once your wallet has finished synchronizing with the nito network, as detailed below.",
    "The Orchard index is not available. Restart Nito Core with -orchardindex=1 before rebuilding private transaction history.",
    "The Orchard index is being prepared. Progress: %.1f%% (%d/%d). Try again in a few minutes before rebuilding private transaction history.",
    "The transparent history index is being prepared. Enable transparent history indexing and wait until it is synced before rebuilding wallet history.",
    "NITOtrings.cpp",
]

TOP_TRANSLATION_FILES = {
    "nito_ar.ts",
    "nito_de.ts",
    "nito_en.ts",
    "nito_es.ts",
    "nito_fr.ts",
    "nito_id.ts",
    "nito_it.ts",
    "nito_ja.ts",
    "nito_ko.ts",
    "nito_nl.ts",
    "nito_pl.ts",
    "nito_pt.ts",
    "nito_pt_BR.ts",
    "nito_ru.ts",
    "nito_tr.ts",
    "nito_uk.ts",
    "nito_zh.ts",
    "nito_zh-Hans.ts",
    "nito_zh_CN.ts",
}

VISIBLE_SYNC_TRANSLATION_GUARDS = [
    "Synchronizing with network…",
    "Connecting to peers…",
    "Number of blocks left",
    "Last block time",
    "Progress",
    "Progress increase per hour",
    "Estimated time left until synced",
    "Hide",
]

TOP_MUST_TRANSLATE_GUARDS = {
    "Source address unavailable",
    "%1 input addresses",
    "Show input addresses",
    "Hide input addresses",
    "Some input addresses are unavailable.",
    "Wallet loading failed.",
    "Some blocks required for complete wallet recovery have been pruned. To reconstruct your wallet and its complete history, use a non-pruned node or perform a full resynchronization. This requires downloading data, time and disk space. No resynchronization has been started.",
    "The Orchard index cannot catch up because required blocks have been pruned. To recover Orchard functionality, use a non-pruned node or explicitly rebuild with -reindex and -prune=0. This requires downloading data, time and disk space. No resynchronization has been started. To continue without Orchard, restart with -orchardindex=0; private balances and spending will be unavailable.",
    "Warning: If you encrypt your wallet and lose your passphrase, you will <b>LOSE ALL OF YOUR NITO</b>!",
    "Are you sure you wish to encrypt your wallet?",
    "Remember that encrypting your wallet cannot fully protect your NITO from being stolen by malware infecting your computer.",
    "Wallet to be encrypted",
    "Your wallet is about to be encrypted. ",
    "This operation needs your wallet passphrase to unlock the wallet.",
    "Opening Wallet <b>%1</b>...",
    "Recent transactions may not yet be visible, and therefore your wallet's balance might be incorrect. This information will be correct once your wallet has finished synchronizing with the Nito network, as detailed below.",
    "Attempting to spend NITO affected by not-yet-displayed transactions will not be accepted by the network.",
    "Enable private Bech32x receiving addresses",
    "Show Bech32x private receiving addresses, private balances and private balance controls after the activation block.",
    "Spend Bech32x private notes. Leave unchecked to spend transparent UTXOs.",
    "Wallet scan in progress. Transparent and private balances may still be loading.",
    "Generates a Bech32x Orchard receiving address starting with nito1x.",
    "Funding source",
    "Private balance",
    "Transparent balance",
    "To review recipient list click \"Show Details...\"",
    "Show Details...",
    "Hide Details...",
    "Multiple recipients",
    "multiple recipients",
    "The private wallet index is not available. Restart Nito Core with private wallet indexing enabled (-orchardindex=1) before using Bech32x wallet features.",
    "Bech32x private note",
    "Bech32x to transparent",
    "Private receiving address metadata is not available yet for this encrypted wallet. Unlock the wallet once or restore it from the recovery phrase to prepare private receiving addresses.",
    "Recovery Phrase",
    "Show Recovery Phrase",
    "The recovery phrase controls the funds derived from its documented scope. Keep wallet.dat backups for V3 or imported transparent keys. Only reveal the phrase in a private place and store it offline.",
    "Write these words down in order. Anyone with this phrase can spend the funds it covers. A wallet upgraded from V3 still requires its wallet.dat backup for older transparent keys.",
}


def xml_escape_source(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def locale_base(path):
    locale = path.stem.removeprefix("nito_")
    if locale.startswith("zh"):
        return "zh"
    return locale.split("_", 1)[0].split("-", 1)[0]


def has_placeholder_corruption(text):
    text = html.unescape(text)
    return bool(
        re.search(r"\?{2,}", text)
        or re.search(r"[A-Za-zÀ-ÿ]\?[A-Za-zÀ-ÿ]", text)
        or re.search(r"\?[A-Za-zÀ-ÿ]", text)
    )


def check_translation_encoding():
    offenders = []
    pattern = re.compile("|".join(MOJIBAKE_PATTERNS))
    paths = sorted(Path("src/qt/locale").glob("*.ts"))
    paths.append(Path("src/qt/nitostrings.cpp"))
    for suffix in ("*.cpp", "*.h", "*.ui"):
        paths.extend(Path("src/qt").glob(suffix))
        paths.extend(Path("src/qt/forms").glob(suffix))
        paths.extend(Path("src/wallet").glob(suffix))
        paths.extend(Path("src/wallet/rpc").glob(suffix))
        paths.extend(Path("src/interfaces").glob(suffix))
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path}:{line_no}: {line.strip()}")
                break
    if offenders:
        print("Qt translation files contain likely mojibake/double-encoded UTF-8:")
        print("\n".join(offenders))
        sys.exit(1)


def check_v4_translation_guards():
    offenders = []
    mojibake_pattern = re.compile("|".join(MOJIBAKE_PATTERNS))
    for path in sorted(Path("src/qt/locale").glob("*.ts")):
        text = path.read_text(encoding="utf-8")
        base_locale = locale_base(path)
        for source in FORBIDDEN_TRANSLATION_SOURCES:
            if f"<source>{xml_escape_source(source)}</source>" in text:
                offenders.append(f"{path}: forbidden corrupted source: {source}")
        for source in V4_TRANSLATION_GUARDS:
            escaped_source = xml_escape_source(source)
            match = re.search(
                r"<source>"
                + re.escape(escaped_source)
                + r"</source>(?:(?!</message>).)*?<translation([^>]*)>(.*?)</translation>",
                text,
                re.DOTALL,
            )
            if not match:
                if path.name in TOP_TRANSLATION_FILES:
                    offenders.append(f"{path}: missing guarded v4 source: {source}")
                continue
            attrs = match.group(1)
            translation = match.group(2).strip()
            if not translation or "\ufffd" in translation or mojibake_pattern.search(translation):
                offenders.append(f"{path}: invalid guarded v4 translation for: {source}")
            if path.name in TOP_TRANSLATION_FILES and base_locale != "en" and has_placeholder_corruption(translation):
                offenders.append(f"{path}: guarded v4 translation contains ASCII '?' replacement characters: {source}")
            if path.name in TOP_TRANSLATION_FILES and "unfinished" in attrs:
                offenders.append(f"{path}: guarded v4 translation is still marked unfinished: {source}")
            if (
                source in TOP_MUST_TRANSLATE_GUARDS
                and path.name in TOP_TRANSLATION_FILES
                and base_locale != "en"
                and html.unescape(translation) == source
            ):
                offenders.append(f"{path}: untranslated guarded v4 source for locale {base_locale}: {source}")
        if path.name in TOP_TRANSLATION_FILES:
            for source in VISIBLE_SYNC_TRANSLATION_GUARDS:
                escaped_source = xml_escape_source(source)
                match = re.search(
                    r"<source>"
                    + re.escape(escaped_source)
                    + r"</source>(?:(?!</message>).)*?<translation([^>]*)>(.*?)</translation>",
                    text,
                    re.DOTALL,
                )
                if not match:
                    continue
                attrs = match.group(1)
                translation = match.group(2).strip()
                if not translation or "\ufffd" in translation or mojibake_pattern.search(translation):
                    offenders.append(f"{path}: invalid visible sync translation for: {source}")
                if "unfinished" in attrs:
                    offenders.append(f"{path}: visible sync translation is still marked unfinished: {source}")
                if base_locale != "en" and has_placeholder_corruption(translation):
                    offenders.append(f"{path}: visible sync translation contains ASCII '?' replacement characters: {source}")
                if base_locale != "en" and html.unescape(translation) == source:
                    offenders.append(f"{path}: untranslated visible sync source for locale {base_locale}: {source}")
    if offenders:
        print("Qt v4 translations are incomplete or contain placeholder corruption:")
        print("\n".join(offenders))
        sys.exit(1)


def check_unfinished_translations_have_no_text():
    offenders = []
    for path in sorted(Path("src/qt/locale").glob("*.ts")):
        tree = ET.parse(path)
        for context in tree.getroot().findall("context"):
            context_name = context.findtext("name", default="")
            for message in context.findall("message"):
                translation = message.find("translation")
                if translation is None or translation.get("type") != "unfinished":
                    continue
                translated_text = "".join(translation.itertext()).strip()
                if translated_text:
                    source = html.unescape(message.findtext("source", default=""))
                    offenders.append(
                        f"{path}: non-empty translation is still marked unfinished in {context_name}: {source}"
                    )
    if offenders:
        print("Qt translation files contain usable translations still marked unfinished:")
        print("\n".join(offenders))
        sys.exit(1)


def check_duplicate_translation_messages():
    offenders = []
    for path in sorted(Path("src/qt/locale").glob("*.ts")):
        tree = ET.parse(path)
        for context in tree.getroot().findall("context"):
            context_name = context.findtext("name", default="")
            seen = {}
            for message in context.findall("message"):
                source = html.unescape(message.findtext("source", default=""))
                comment = html.unescape(message.findtext("comment", default=""))
                key = (source, comment)
                seen[key] = seen.get(key, 0) + 1
            for (source, _comment), count in seen.items():
                if count > 1:
                    offenders.append(
                        f"{path}: duplicate source in context {context_name}: {source}"
                    )
    if offenders:
        print("Qt translation files contain duplicate messages that make lrelease warn:")
        print("\n".join(offenders))
        sys.exit(1)


def main():
    check_translation_encoding()
    check_v4_translation_guards()
    check_unfinished_translations_have_no_text()
    check_duplicate_translation_messages()

    tr_strings = subprocess.run(['git', 'grep', '-e', 'tr("[[:space:]]', '--', 'src/qt'], stdout=subprocess.PIPE, text=True).stdout

    if tr_strings.strip():
        print("Avoid leading whitespaces in:")
        print(tr_strings)
        sys.exit(1)


if __name__ == "__main__":
    main()
