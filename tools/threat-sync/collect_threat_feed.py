#!/usr/bin/env python3
"""Collect, normalize, and emit SecureVault threat-feed payload JSON.

This collector is intentionally detached from the desktop app. It only creates
the unsigned payload consumed by tools/feed-signer.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import logging
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

LOG = logging.getLogger("threat-sync")

SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
URLHAUS_RECENT_PAYLOADS_TEMPLATE = (
    "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
)

EXTENSION_PATTERN = re.compile(r"(?<![a-z0-9_.-])\.([a-z0-9][a-z0-9_+{}-]{1,31})(?![a-z0-9_-])", re.I)
ARCHIVE_OR_PAYLOAD_EXTENSIONS = {
    ".7z",
    ".bat",
    ".cmd",
    ".dll",
    ".docm",
    ".exe",
    ".hta",
    ".iso",
    ".js",
    ".lnk",
    ".msi",
    ".ps1",
    ".rar",
    ".scr",
    ".vbs",
    ".xlsm",
    ".zip",
}
BUILTIN_RANSOMWARE_EXTENSIONS = {
    ".8base": "8base",
    ".akira": "akira",
    ".arena": "arena",
    ".basta": "black-basta",
    ".blackcat": "blackcat",
    ".cerber": "cerber",
    ".conti": "conti",
    ".crypt": "generic-cryptor",
    ".crypted": "generic-cryptor",
    ".cryp1": "cryptxxx",
    ".dharma": "dharma",
    ".djvu": "stop-djvu",
    ".lockbit": "lockbit",
    ".lockbit3": "lockbit",
    ".locked": "generic-locker",
    ".locky": "locky",
    ".mallox": "mallox",
    ".odin": "locky",
    ".phobos": "phobos",
    ".revil": "revil",
    ".ryuk": "ryuk",
    ".stop": "stop-djvu",
    ".wallet": "dharma",
    ".wcry": "wannacry",
    ".wncry": "wannacry",
    ".zepto": "locky",
}


@dataclass(frozen=True)
class FetchResult:
    name: str
    url: str
    ok: bool
    body: str = ""
    status: int | None = None
    error: str | None = None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(ts: datetime) -> str:
    return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_feed_version(ts: datetime) -> str:
    return ts.strftime("%Y.%m.%d.%H%MZ")


def split_env_urls(value: str | None) -> list[str]:
    if not value:
        return []
    candidates = re.split(r"[\n,]+", value)
    return [candidate.strip() for candidate in candidates if candidate.strip()]


def redact_url(url: str, auth_key: str | None = None) -> str:
    if auth_key:
        return url.replace(auth_key, "REDACTED")
    return url


async def fetch_text(name: str, url: str, *, auth_key: str | None = None) -> FetchResult:
    safe_url = redact_url(url, auth_key)
    LOG.info("[%s] fetching %s", name, safe_url)

    def _request() -> FetchResult:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "text/plain, application/json, text/csv;q=0.9, */*;q=0.5",
                "User-Agent": "SecureVaultUltimate-ThreatSync/0.1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
                status = getattr(response, "status", None)
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    return FetchResult(name, safe_url, False, status=status, error="response too large")
                text = body.decode("utf-8", errors="replace")
                return FetchResult(name, safe_url, 200 <= int(status or 0) < 300, text, status)
        except urllib.error.HTTPError as exc:
            return FetchResult(name, safe_url, False, status=exc.code, error=str(exc))
        except urllib.error.URLError as exc:
            return FetchResult(name, safe_url, False, error=str(exc.reason))
        except TimeoutError:
            return FetchResult(name, safe_url, False, error="timeout")

    return await asyncio.to_thread(_request)


def normalize_extension(value: str) -> str | None:
    value = value.strip().lower()
    if not value:
        return None
    if not value.startswith("."):
        value = f".{value}"
    if not EXTENSION_PATTERN.fullmatch(value):
        return None
    if len(value) > 33:
        return None
    return value


def extract_extensions_from_text(text: str) -> set[str]:
    found: set[str] = set()
    for match in EXTENSION_PATTERN.finditer(text):
        extension = normalize_extension(match.group(0))
        if extension:
            found.add(extension)
    return found


def extract_extensions_from_json(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for child in value.values():
            found.update(extract_extensions_from_json(child))
    elif isinstance(value, list):
        for child in value:
            found.update(extract_extensions_from_json(child))
    elif isinstance(value, str):
        found.update(extract_extensions_from_text(value))
    return found


def parse_extension_feed(result: FetchResult) -> set[str]:
    if not result.ok:
        LOG.warning("[%s] skipped: %s", result.name, result.error or result.status)
        return set()

    try:
        parsed = json.loads(result.body)
    except json.JSONDecodeError:
        extensions = extract_extensions_from_text(result.body)
    else:
        extensions = extract_extensions_from_json(parsed)

    LOG.info("[%s] parsed %d candidate extensions", result.name, len(extensions))
    return extensions


def parse_urlhaus_payload_extensions(result: FetchResult) -> set[str]:
    if not result.ok:
        LOG.warning("[%s] skipped: %s", result.name, result.error or result.status)
        return set()

    cleaned = "\n".join(
        line for line in result.body.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    reader = csv.reader(io.StringIO(cleaned))
    extensions: set[str] = set()
    rows = 0
    for row in reader:
        rows += 1
        for cell in row:
            text = urllib.parse.unquote(cell.strip())
            for extension in extract_extensions_from_text(text):
                if extension in ARCHIVE_OR_PAYLOAD_EXTENSIONS:
                    extensions.add(extension)
    LOG.info("[%s] scanned %d CSV rows and found %d malware payload extensions", result.name, rows, len(extensions))
    return extensions


async def collect_remote_sources(args: argparse.Namespace) -> tuple[list[FetchResult], set[str], set[str]]:
    tasks = []
    if args.urlhaus_auth_key:
        url = args.urlhaus_recent_payloads_url or URLHAUS_RECENT_PAYLOADS_TEMPLATE.format(
            auth_key=urllib.parse.quote(args.urlhaus_auth_key, safe="")
        )
        tasks.append(fetch_text("urlhaus-recent-payloads", url, auth_key=args.urlhaus_auth_key))
    else:
        LOG.warning("[urlhaus-recent-payloads] URLHAUS_AUTH_KEY is not set; source disabled")

    extension_urls = list(args.extension_feed_url)
    extension_urls.extend(split_env_urls(os.getenv("RANSOMWARE_EXTENSION_FEED_URLS")))
    for index, url in enumerate(dict.fromkeys(extension_urls), start=1):
        tasks.append(fetch_text(f"ransomware-extension-feed-{index}", url))

    if not tasks:
        return [], set(), set()

    results = await asyncio.gather(*tasks)
    ransomware_extensions: set[str] = set()
    malware_payload_extensions: set[str] = set()

    for result in results:
        if result.name == "urlhaus-recent-payloads":
            malware_payload_extensions.update(parse_urlhaus_payload_extensions(result))
        else:
            ransomware_extensions.update(parse_extension_feed(result))

    return list(results), ransomware_extensions, malware_payload_extensions


def load_trusted_processes(path: Path | None) -> list[dict[str, Any]]:
    if not path:
        return []
    LOG.info("[trusted-processes] loading %s", path)
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        data = data.get("trustedProcesses", [])
    if not isinstance(data, list):
        raise ValueError("trusted process file must be a JSON array or object with trustedProcesses")
    return data


def build_ransomware_records(
    remote_extensions: Iterable[str],
    *,
    include_builtin: bool,
    max_extensions: int,
) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    if include_builtin:
        for extension, family in BUILTIN_RANSOMWARE_EXTENSIONS.items():
            records[extension] = {
                "extension": extension,
                "family": family,
                "severity": "high",
                "firstSeenUtc": None,
                "notes": "Built-in bootstrap indicator retained until remote ransomware-extension feeds supersede it.",
            }

    for extension in sorted(remote_extensions):
        normalized = normalize_extension(extension)
        if not normalized:
            continue
        records[normalized] = {
            "extension": normalized,
            "family": "open-source-feed",
            "severity": "high",
            "firstSeenUtc": None,
            "notes": "Normalized from configured open-source ransomware extension feed.",
        }

    return list(sorted(records.values(), key=lambda item: item["extension"]))[:max_extensions]


def build_yara_rules(malware_payload_extensions: Iterable[str]) -> list[dict[str, Any]]:
    payload_exts = ", ".join(sorted(malware_payload_extensions)) or "none"
    return [
        {
            "id": "secure-vault-mass-rename-burst-v1",
            "name": "SecureVault Mass Rename Burst",
            "severity": "high",
            "rule": (
                'rule SecureVaultMassRenameBurst { meta: source = "secure-vault-threat-sync" '
                'description = "Behavioral engine placeholder; host app evaluates file-event bursts." '
                "condition: false }"
            ),
            "description": "Placeholder for short-window bulk rename/write behavior detection.",
        },
        {
            "id": "urlhaus-recent-payload-extension-context-v1",
            "name": "URLHaus Recent Payload Extension Context",
            "severity": "medium",
            "rule": (
                'rule URLHausRecentPayloadExtensionContext { meta: source = "urlhaus" '
                f'payload_extensions = "{payload_exts}" condition: false }}'
            ),
            "description": "Non-blocking context generated from recent malware payload filenames.",
        },
    ]


def build_payload(args: argparse.Namespace, results: list[FetchResult], ransomware_extensions: set[str], malware_payload_extensions: set[str]) -> dict[str, Any]:
    now = utc_now()
    successful_sources = [result.name for result in results if result.ok]
    failed_sources = [
        {
            "name": result.name,
            "url": result.url,
            "status": result.status,
            "error": result.error,
        }
        for result in results
        if not result.ok
    ]
    records = build_ransomware_records(
        ransomware_extensions,
        include_builtin=args.include_builtin,
        max_extensions=args.max_extensions,
    )
    if not records:
        raise ValueError("no ransomware extension records survived normalization")

    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "feedVersion": args.feed_version or default_feed_version(now),
        "publishedUtc": iso_utc(now),
        "ransomwareExtensions": records,
        "yaraRules": build_yara_rules(malware_payload_extensions),
        "trustedProcesses": load_trusted_processes(args.trusted_processes),
        "revokedFeedVersions": [],
        "minimumClientSchemaVersion": 1,
        "sourceSummary": {
            "successfulSources": successful_sources,
            "failedSources": failed_sources,
            "remoteRansomwareExtensionCount": len(ransomware_extensions),
            "urlhausPayloadExtensionCount": len(malware_payload_extensions),
            "builtinBootstrapEnabled": args.include_builtin,
        },
    }
    return payload


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as temp_file:
        json.dump(payload, temp_file, ensure_ascii=False, indent=2, sort_keys=True)
        temp_file.write("\n")
        temp_name = temp_file.name
    Path(temp_name).replace(path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build unsigned SecureVault threat payload JSON")
    parser.add_argument("--out", type=Path, required=True, help="Output threat_payload.json path")
    parser.add_argument("--feed-version", help="Override generated feedVersion")
    parser.add_argument("--urlhaus-auth-key", default=os.getenv("URLHAUS_AUTH_KEY"))
    parser.add_argument("--urlhaus-recent-payloads-url", default=os.getenv("URLHAUS_RECENT_PAYLOADS_URL"))
    parser.add_argument("--extension-feed-url", action="append", default=[], help="Additional text/JSON ransomware extension feed URL")
    parser.add_argument("--trusted-processes", type=Path, help="Optional trustedProcesses JSON file")
    parser.add_argument("--max-extensions", type=int, default=250)
    parser.add_argument("--require-remote", action="store_true", help="Fail if every remote source is disabled or failed")
    parser.add_argument("--include-builtin", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--log-level", default=os.getenv("THREAT_SYNC_LOG_LEVEL", "INFO"))
    return parser.parse_args(argv)


async def async_main(argv: list[str]) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )

    LOG.info("[collector] starting threat feed collection")
    results, ransomware_extensions, malware_payload_extensions = await collect_remote_sources(args)
    remote_success = any(result.ok for result in results)
    if args.require_remote and not remote_success:
        LOG.error("[collector] no remote source succeeded while --require-remote is enabled")
        return 2

    payload = build_payload(args, results, ransomware_extensions, malware_payload_extensions)
    write_json_atomic(args.out, payload)
    LOG.info("[parser] wrote %s", args.out)
    LOG.info("[parser] ransomwareExtensions=%d yaraRules=%d trustedProcesses=%d", len(payload["ransomwareExtensions"]), len(payload["yaraRules"]), len(payload["trustedProcesses"]))
    return 0


def main() -> int:
    try:
        return asyncio.run(async_main(sys.argv[1:]))
    except Exception:
        LOG.exception("[fatal] threat feed collection failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
