#!/usr/bin/env python3
import json, re, sys, urllib.request

CISA_KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
try:
  with urllib.request.urlopen(CISA_KEV) as r:
    kev = json.load(r)
  entries = kev.get('vulnerabilities', [])
  brow = []
  for e in entries:
    prod = (e.get('product') or '') + ' ' + (e.get('vendorProject') or '')
    if re.search(r"chrome|chromium|v8", prod, re.I):
      brow.append({
        'cve': e.get('cveID'),
        'vendor': e.get('vendorProject'),
        'product': e.get('product'),
        'dateAdded': e.get('dateAdded'),
        'shortDescription': e.get('shortDescription'),
        'requiredAction': e.get('requiredAction')
      })
except Exception as ex:
  print('CISA KEV fetch failed:', ex, file=sys.stderr)
  brow = []

with open('data/cves.json', 'w') as f:
  json.dump({'itw_chrome_related': brow}, f, indent=2)

print('[cves] wrote data/cves.json with', len(brow), 'ITW rows')
