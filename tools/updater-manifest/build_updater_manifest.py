#!/usr/bin/env python3
"""Build a Tauri-compatible updater manifest from GitHub Release assets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


WINDOWS_EXTENSIONS = (".exe", ".msi", ".zip")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SecureVault updater.json")
    parser.add_argument("--event", required=True, help="Path to GITHUB_EVENT_PATH JSON")
    parser.add_argument("--out", required=True, help="Output updater.json path")
    parser.add_argument("--asset-dir", help="Directory containing downloaded release assets")
    args = parser.parse_args()

    event = load_json(Path(args.event))
    release = event.get("release") or {}
    assets = release.get("assets") or []
    version = normalize_version(release.get("tag_name") or release.get("name") or "")
    if not version:
        raise SystemExit("release tag/name is missing")

    asset_dir = Path(args.asset_dir) if args.asset_dir else None
    signature_by_name = {
        asset["name"][:-4]: fetch_signature(asset, asset_dir)
        for asset in assets
        if isinstance(asset.get("name"), str) and asset["name"].endswith(".sig")
    }
    platforms: dict[str, dict[str, str]] = {}
    for asset in assets:
        name = asset.get("name")
        if not isinstance(name, str) or name.endswith(".sig"):
            continue
        if not is_windows_asset(name):
            continue
        signature = signature_by_name.get(name)
        url = asset.get("browser_download_url")
        if not signature or not url:
            continue
        platforms["windows-x86_64"] = {"signature": signature, "url": url}
        break

    if not platforms:
        raise SystemExit("no signed windows-x86_64 release asset found")

    manifest = {
        "version": version,
        "notes": release.get("body") or "SecureVault Ultimate update",
        "pub_date": release.get("published_at") or release.get("created_at"),
        "platforms": platforms,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit("event JSON root must be an object")
    return data


def normalize_version(raw: str) -> str:
    return raw.strip().lstrip("v")


def is_windows_asset(name: str) -> bool:
    lowered = name.lower()
    return "x64" in lowered and lowered.endswith(WINDOWS_EXTENSIONS)


def fetch_signature(asset: dict[str, Any], asset_dir: Path | None) -> str:
    name = asset.get("name")
    if asset_dir and isinstance(name, str):
        path = asset_dir / name
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    local_path = asset.get("local_path")
    if isinstance(local_path, str):
        path = Path(local_path)
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    body = asset.get("body")
    if isinstance(body, str) and body.strip():
        return body.strip()
    return ""


if __name__ == "__main__":
    sys.exit(main())
