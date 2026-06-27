#!/usr/bin/env python3
import json, os, re, time, random, base64
from urllib.parse import quote
import urllib.request, urllib.error
from datetime import datetime

GCS_LIST = "https://storage.googleapis.com/storage/v1/b/chromium-browser-asan/o"
PREFIXES = [
    "linux-release/",
    "mac-release/",
    "mac-release-arm64/",
    "linux-release-v8-arm/",
    "linux-release-v8-sandbox-testing/",
    "linux-release-chromeos/",
    "win32-release_x64/",
#    "ios-release/",  # removed - ASan builds for ios no longer maintained by Google
]

HEADERS = {
    "User-Agent": "fetch-builds/mini",
    "Accept": "application/json",
}

ID_RE = re.compile(r"(\d+)\.zip$")

# ---------- helpers ----------

def parse_updated(ts: str) -> float:
    """Return unix ts for RFC3339 (with/without millis)."""
    if not ts:
        return 0.0
    ts = ts.replace("Z", "+00:00")
    try:
        # Python handles both with/without fractional seconds
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return 0.0

def b64_md5_to_hex(b64val: str) -> str:
    if not b64val:
        return ""
    try:
        return base64.b64decode(b64val).hex()
    except Exception:
        return ""

def fetch_with_retries(url: str, max_attempts: int = 6, base_sleep: float = 0.6, timeout: float = 30.0):
    """Fetch URL with exponential backoff + jitter."""
    last_err = None
    for attempt in range(1, max_attempts + 1):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except (urllib.error.URLError, urllib.error.HTTPError, ConnectionResetError) as e:
            last_err = e
            # 4xx other than 429 usually won't succeed on retry; still retry small times.
            sleep = base_sleep * (2 ** (attempt - 1))
            sleep *= (0.8 + random.random() * 0.4)  # jitter 0.8x–1.2x
            print(f"[builds] fetch attempt {attempt} failed: {e}. retrying in {sleep:.2f}s …")
            time.sleep(min(sleep, 8.0))
    raise last_err

# ---------- GCS list paging ----------

def gcs_list_one(prefix: str, page_token: str | None = None, max_results: int = 1000):
    url = (f"{GCS_LIST}?prefix={quote(prefix)}"
           f"&fields=items(name,md5Hash,metadata,updated,generation),nextPageToken"
           f"&maxResults={max_results}")
    if page_token:
        url += f"&pageToken={quote(page_token)}"
    return fetch_with_retries(url)

def gcs_list_all(prefix: str):
    items = []
    token = None
    # Walk all pages so we truly see the newest object
    while True:
        data = gcs_list_one(prefix, token, max_results=1000)
        page = data.get("items", [])
        items.extend(page)
        token = data.get("nextPageToken")
        if not token:
            break
    return items

def build_id_from_name(name: str) -> int:
    m = ID_RE.search(name or "")
    return int(m.group(1)) if m else -1

def best_item(items):
    # Keep only zip artifacts (asan artifacts are zips in this bucket)
    zips = [it for it in (items or []) if (it.get("name") or "").endswith(".zip")]
    if not zips:
        return None
    # Choose newest by updated → generation → numeric build id
    zips.sort(
        key=lambda it: (
            parse_updated(it.get("updated")),
            int(it.get("generation", "0")),
            build_id_from_name(it.get("name", "")),
        ),
        reverse=True,
    )
    return zips[0]

def make_download(item):
    # Robust download link with encoded object name + generation (works for iOS too)
    obj = quote(item["name"], safe="")
    gen = item.get("generation")
    return f"https://www.googleapis.com/download/storage/v1/b/chromium-browser-asan/o/{obj}?generation={gen}&alt=media"

def one_row_for_prefix(prefix: str):
    print(f"[builds] listing {prefix} …")
    items = gcs_list_all(prefix)
    item = best_item(items)
    if not item:
        print(f"[builds] no ZIP items under {prefix}")
        return None
    meta = item.get("metadata", {}) or {}
    name = item.get("name", "")
    row = {
        "platform": prefix.rstrip("/"),
        "arch": ("arm64" if "arm64" in prefix else
                 "arm"   if "-arm"   in prefix else
                 "x64"),
        "filename": os.path.basename(name),
        "id": (ID_RE.search(name).group(1) if ID_RE.search(name) else None),
        "commit": meta.get("cr-git-commit") or meta.get("git-commit") or "",
        "updated": item.get("updated"),
        "md5_hex": b64_md5_to_hex(item.get("md5Hash", "")),
        "download": make_download(item),
    }
    print(f"[builds] latest {prefix} → {row['filename']}  updated={row['updated']}  id={row['id']}")
    return row

# ---------- main ----------

def main():
    out = {"asan_latest": {}}
    for p in PREFIXES:
        try:
            row = one_row_for_prefix(p)
        except Exception as e:
            print(f"[builds] ERROR listing {p}: {e}")
            continue
        if not row:
            continue
        plat_key = (
            "linux"    if p.startswith("linux-release/") else
            "mac"      if p.startswith("mac-release/") else
            "mac"      if p.startswith("mac-release-arm64/") else
            "windows"  if p.startswith("win32-release_x64/") else
            "chromeos" if p.startswith("linux-release-chromeos/") else
            "ios"      if p.startswith("ios-release/") else
            "linux"    # fallback for v8-arm, v8-sandbox-testing
        )
        arch_key = ("arm64" if "arm64" in p else "arm" if "-arm" in p else "x64")
        out["asan_latest"].setdefault(plat_key, {})[arch_key] = row

    os.makedirs("data", exist_ok=True)
    with open("data/builds.json", "w") as f:
        json.dump(out, f, indent=2)
    total = sum(len(v) for v in out["asan_latest"].values())
    print(f"[builds] wrote data/builds.json with {total} latest rows")

if __name__ == "__main__":
    main()
