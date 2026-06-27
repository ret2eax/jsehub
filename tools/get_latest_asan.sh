#!/usr/bin/env bash
set -euo pipefail
DEST="${1:-./asan-d8}"
API_BASE="https://storage.googleapis.com/storage/v1/b/chromium-browser-asan/o"
QUERY="${API_BASE}?prefix=linux-release/&fields=items(name,updated,md5Hash),nextPageToken&maxResults=1000"
json_all=$(mktemp); : > "$json_all"
page_url="$QUERY"
while :; do
  page=$(curl -fsSL "$page_url")
  echo "$page" | jq -c '.items // [] | .[]' >> "$json_all"
  tok=$(echo "$page" | jq -r '.nextPageToken // empty')
  [[ -z "$tok" ]] && break
  page_url="$QUERY&pageToken=$(printf '%s' "$tok" | jq -sRr @uri)"
done
line=$(jq -r 'select(.name|test("^linux-release/asan-linux-release-[0-9]+\\.zip$")) |
  .name as $n | capture("asan-linux-release-(?<id>[0-9]+)\\.zip") | "\(.id)\t\($n)"' "$json_all" \
  | sort -nr | head -n1)
id="${line%%	*}"; name="${line#*	}"
enc="$(jq -rn --arg s "$name" '$s|@uri')"
url="https://www.googleapis.com/download/storage/v1/b/chromium-browser-asan/o/$enc?alt=media"
echo "[i] Downloading $name -> $DEST"
mkdir -p "$DEST"
curl -fL -o /tmp/asan.zip "$url"
unzip -o /tmp/asan.zip -d "$DEST" >/dev/null
echo "[✓] Extracted to $DEST"
